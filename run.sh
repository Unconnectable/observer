#sudo RUST_LOG=info ./target/release/observer --pid $(pgrep -n websocket)
sudo RUST_LOG=info ./target/release/observer #观测所有


#sudo RUST_LOG=info ./target/release/observer --pid 62727
#sudo RUST_LOG=info ./target/release/observer --pid $(pgrep -n websocket)
#sudo RUST_LOG=info ./target/release/observer --pid 67418