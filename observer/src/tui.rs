//! 实时界面: 顶部全局速率, 中间按 PID 的明细表, 底部最近事件.
//! 界面自己不记账, 数据全部从 Metrics 现取, 所以纯文本模式的数字不受它影响.
use crate::stats::{Metrics, Sample};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Cell, List, ListItem, Paragraph, Row, Table},
    Frame, Terminal,
};
use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 最近事件面板留多少行
pub const RING_MAX: usize = 200;
/// 明细表最多列几个进程, 再多屏幕装不下
const TOP_ROWS: usize = 14;

pub type Recent = Arc<Mutex<VecDeque<String>>>;

/// 进 alternate screen 画到用户退出, 返回时终端一定已经恢复原状
pub fn run(metrics: Arc<Metrics>, recent: Recent, stop: Arc<AtomicBool>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = draw_loop(&mut terminal, &metrics, &recent, &stop);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn draw_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<Stdout>>,
    metrics: &Arc<Metrics>,
    recent: &Recent,
    stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let mut prev = metrics.snapshot();
    let mut paused = false;

    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        let cur = metrics.snapshot();
        let header = header_lines(&prev, &cur, metrics, paused);
        let rows = table_rows(metrics);
        let tail: Vec<String> = recent
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default();

        terminal.draw(|frame| render(frame, header, rows, tail))?;

        if !paused {
            prev = cur;
        }

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            stop.store(true, Ordering::Relaxed);
                            return Ok(());
                        }
                        // 空格/p: 冻结画面但继续收事件, 速率栏停在暂停那一刻
                        KeyCode::Char('p') | KeyCode::Char(' ') => paused = !paused,
                        _ => {}
                    }
                }
            }
        }
    }
}

fn render(frame: &mut Frame, header: Vec<String>, rows: Vec<Row<'static>>, tail: Vec<String>) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(4),
                Constraint::Min(8),
                Constraint::Min(6),
            ]
            .to_vec(),
        )
        .split(area);

    let block = Block::bordered().title(" observer  (q 退出, p 暂停刷新) ");
    let lines: Vec<Line> = header.into_iter().map(Line::from).collect();
    frame.render_widget(Paragraph::new(lines).block(block), chunks[0]);

    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Min(16),
                Constraint::Length(10),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(10),
            ],
        )
        .header(Row::new(vec![
            Cell::from("PID"),
            Cell::from("进程"),
            Cell::from("事件数"),
            Cell::from("下行"),
            Cell::from("上行"),
            Cell::from("重传"),
            Cell::from("RST"),
            Cell::from("按住"),
        ]))
        .block(Block::bordered().title(" 按 PID 明细 (按字节多少排序) "))
        .column_spacing(1),
        chunks[1],
    );

    let items: Vec<ListItem> = tail.into_iter().rev().map(|l| ListItem::new(l)).collect();
    frame.render_widget(
        List::new(items).block(Block::bordered().title(" 最近事件 (最新在上面) ")),
        chunks[2],
    );
}

/// 顶部那块: 第一行是当下这一秒, 第二行是累计与两类稀有事件
fn header_lines(prev: &Sample, cur: &Sample, metrics: &Metrics, paused: bool) -> Vec<String> {
    let dt = (cur.secs - prev.secs).max(0.001);
    let rx = cur.rx_bytes.saturating_sub(prev.rx_bytes) as f64 / 1024.0 / dt;
    let tx = cur.tx_bytes.saturating_sub(prev.tx_bytes) as f64 / 1024.0 / dt;
    let mut events = 0u64;
    for (c, p) in cur.hits.iter().zip(prev.hits.iter()) {
        events += c.saturating_sub(*p);
    }
    let retrans = cur.hits[crate::TrafficDirection::Retransmit as usize];
    let blocked = metrics.blocked_ms_total();
    let stamp = if paused { "[已暂停刷新] " } else { "" };

    vec![
        format!(
            "{}跑了 {:.0} s   这一秒 {} 条/s  ↓{:.1} KB/s  ↑{:.1} KB/s",
            stamp,
            cur.secs,
            events as f64 / dt,
            rx,
            tx
        ),
        format!(
            "累计 ↓{}  ↑{}   重传 {} 次(其中 {} 次在中断里, 归不到进程)   发不出去 {}",
            Metrics::human(cur.rx_bytes as f64),
            Metrics::human(cur.tx_bytes as f64),
            retrans,
            metrics.retrans_irq_total(),
            Metrics::human_ms(blocked),
        ),
    ]
}

/// 明细表: 取字节最多的前 TOP_ROWS 个进程
fn table_rows(metrics: &Metrics) -> Vec<Row<'static>> {
    let rows = metrics.pid_rows();
    let mut out = Vec::new();
    for r in rows.iter().take(TOP_ROWS) {
        let blocked = r.blocked_ns as f64 / 1_000_000.0;
        let mut cells = vec![
            Cell::from(r.pid.to_string()),
            Cell::from(short_name(&r.comm)),
            Cell::from(r.events.to_string()),
            Cell::from(Metrics::human(r.rx_bytes as f64)),
            Cell::from(Metrics::human(r.tx_bytes as f64)),
            Cell::from(r.retrans.to_string()),
            Cell::from(r.rst.to_string()),
        ];
        let blocked_cell = if r.blocked_ns == 0 {
            Cell::from("-")
        } else {
            // 按住过就用醒目颜色, 这是这一屏里最该被看见的一格
            Cell::from(Metrics::human_ms(blocked)).style(Style::default().fg(Color::Yellow))
        };
        cells.push(blocked_cell);
        let style = if r.retrans > 0 {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        out.push(Row::new(cells).style(style));
    }
    if rows.len() > TOP_ROWS {
        out.push(Row::new(vec![Cell::from(format!(
            "…另有 {} 个进程没显示",
            rows.len() - TOP_ROWS
        ))
        .style(Style::default().add_modifier(Modifier::DIM))]))
    }
    out
}

fn short_name(comm: &str) -> String {
    if comm.chars().count() > 15 {
        let cut: String = comm.chars().take(14).collect();
        format!("{}…", cut)
    } else {
        comm.to_string()
    }
}
