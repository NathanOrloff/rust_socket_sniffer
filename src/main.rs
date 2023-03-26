use pcap::{Device, Capture};
use argparse::{ArgumentParser, StoreTrue, Store};
use std::process::exit;
use std::result::Result;
use std::str;
use pktparse;

fn main() {

    //get base device
    let mut target_device: Device = Device::lookup().unwrap().unwrap();
    let mut list_devices: bool = false;
    let mut requested_device = "".to_string();
    //parser args
    {
        let mut parser = ArgumentParser::new();
        parser.set_description("Network sniffer arguments");
        parser.refer(&mut requested_device)
            .add_option(&["-t", "--target-device"], Store, "Device to target");
        parser.refer(&mut list_devices)
            .add_option(&["-l", "--list-devices"], StoreTrue, "List available devices to sniff");
        parser.parse_args_or_exit();
    }

    if list_devices {
        list_available_devices();
        exit(0);
    }

    //get desired device and start capture
    if !requested_device.is_empty() { 
        target_device = get_requested_device(requested_device).unwrap();
        println!("{:?}", target_device);
    }

    //sniff, parse &[u8] data and print
    sniff_device(target_device);
}

fn list_available_devices() {
    let device_list = Device::list().unwrap();
    println!("{:#?}", device_list);
}

fn get_requested_device(requested_device: String) -> Result<Device, &'static str> {
    let device_list = Device::list().unwrap();
    for device in device_list {
        if device.name == requested_device {
            let ret_device = device.clone();
            return Ok(ret_device);
        }
    }
    Err("Requested device not found")
}

fn sniff_device(device: Device) {
    let mut cap = Capture::from_device(device).unwrap().open().unwrap();
    while let Ok(packet) = cap.next_packet() {
        if let Ok((remaining, eth_frame)) = pktparse::ethernet::parse_ethernet_frame(packet.data) {
            println!("Ethernet Header:");
            println!("Source Mac Address: {:02X?}, Destination Mac Address: {:02X?}", eth_frame.source_mac.0, eth_frame.dest_mac.0);

            if eth_frame.ethertype == pktparse::ethernet::EtherType::IPv4 {
                if let Ok((remaining, ipv4_packet)) = pktparse::ipv4::parse_ipv4_header(remaining) {
                    println!("\tIPv4 Header:");
                    println!("\t\tVersion: {}, Header Length: {}, TTL: {}", ipv4_packet.version, ipv4_packet.length, ipv4_packet.ttl);
                    println!("\t\tProtocol: {:?}, Source: {:?}, Destination: {:?}", ipv4_packet.protocol, ipv4_packet.source_addr, ipv4_packet.dest_addr);
                
                    if ipv4_packet.protocol == pktparse::ip::IPProtocol::UDP {
                        if let Ok((remaining, udp_packet)) = pktparse::udp::parse_udp_header(remaining) {
                            println!("\tUDP Header:");
                            println!("\t\tSource Port: {}, Destination Port: {}, Length: {}", udp_packet.source_port, udp_packet.dest_port, udp_packet.length);
                            println!("\t\tData:");
                            data_print(&remaining, "\t\t\t", 20).unwrap();
                        }
                    }

                    else if ipv4_packet.protocol == pktparse::ip::IPProtocol::TCP {
                        if let Ok((remaining, tcp_packet)) = pktparse::tcp::parse_tcp_header(remaining) {
                            println!("\tTCP Header:");
                            println!("\t\tSource Port: {}, Destination Port: {}", tcp_packet.source_port, tcp_packet.dest_port);
                            println!("\t\tSequence: {}, Achnowledgement: {}", tcp_packet.sequence_no, tcp_packet.ack_no);
                            println!("\t\tFlags:");
                            println!("\t\t\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}", tcp_packet.flag_urg, tcp_packet.flag_ack, tcp_packet.flag_psh, tcp_packet.flag_rst, tcp_packet.flag_syn, tcp_packet.flag_fin);
                            println!("\t\tData:");
                            data_print(&remaining, "\t\t\t", 20).unwrap();
                        }
                    }
                    else {
                        println!("\tData:");
                        data_print(&remaining, "\t\t", 20).unwrap();
                    }
                }
            } 
            else {
                println!("\tData:");
                data_print(&remaining, "\t\t", 20).unwrap();
            }
            println!();
        }
        else {
            println!("\tData:");
            data_print(&packet.data, "\t\t", 20).unwrap();
        }
    }
}

fn data_print(data: &[u8], prefix: &str, length: u8) -> Result<(), &'static str>{
    let prefix_len: u8 = prefix.len().try_into().unwrap();
    let length = length - prefix_len;
    if length < 1 {
        return Err("line length too short");
    }
    let mut index = 0;
    let mut out_str = prefix.clone().to_owned();
    for d in data {
        out_str.push_str(&*format!("\\0x{:02x}", d.clone()));
        index = index + 1;

        if index == length {
            println!("{}", out_str);
            index = 0;
            out_str = prefix.clone().to_owned();
        }
    }
    return Ok(());
}

