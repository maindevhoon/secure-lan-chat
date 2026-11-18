# FTP over TCP Reno on sender -> router -> receiver.
if {$argc != 4} {
    puts stderr "usage: ns tcp.tcl delay_ms loss_probability seed trace_file"
    exit 1
}
lassign $argv delay loss seed path
ns-random $seed
set sim [new Simulator]
set trace [open $path w]
$sim trace-all $trace
set sender [$sim node]
set router [$sim node]
set receiver [$sim node]
$sim duplex-link $sender $router 10Mb 2ms DropTail
$sim duplex-link $router $receiver 2Mb ${delay}ms DropTail
$sim queue-limit $router $receiver 250
if {$loss > 0} {
    set errors [new ErrorModel]
    $errors unit pkt
    $errors set rate_ $loss
    $errors ranvar [new RandomVariable/Uniform]
    $errors drop-target [new Agent/Null]
    $sim link-lossmodel $errors $router $receiver
}
set tcp [new Agent/TCP/Reno]
$tcp set packetSize_ 1000
$tcp set window_ 128
set sink [new Agent/TCPSink]
$sim attach-agent $sender $tcp
$sim attach-agent $receiver $sink
$sim connect $tcp $sink
set ftp [new Application/FTP]
$ftp attach-agent $tcp
proc finish {} {
    global sim trace
    $sim flush-trace
    close $trace
    exit 0
}
$sim at 0.5 "$ftp start"
$sim at 10.5 "finish"
$sim run
