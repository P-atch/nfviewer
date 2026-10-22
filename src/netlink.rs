use libc::{
    AF_NETLINK, NETLINK_NETFILTER, NFNETLINK_V0, NFNL_SUBSYS_QUEUE, NFPROTO_IPV4, NFQA_CFG_PARAMS,
    NFQA_VERDICT_HDR, NFQNL_COPY_PACKET, NFQNL_MSG_CONFIG, NFQNL_MSG_VERDICT, NLM_F_ACK,
    NLM_F_REQUEST, SOCK_RAW, bind, iovec, msghdr, nlmsgerr, nlmsghdr, recvmsg, sa_family_t,
    sendmsg, size_t, sockaddr, sockaddr_nl, socket, socklen_t,
};
use std::ffi::{c_int, c_void};
use std::mem::zeroed;
use std::ptr;
use std::ptr::null_mut;

//const NLMSG_NOOP: u16 = 0x1; /* Nothing.		*/
//const NLMSG_ERROR: u16 = 0x2; /* Error		*/
//const NLMSG_DONE: u16 = 0x3; /* End of a dump	*/
//const NLMSG_OVERRUN: u16 = 0x4; /* Data lost		*/

const NFQA_CFG_CMD: u16 = 1;
const NFQNL_CFG_CMD_BIND: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NfGenMsg {
    pub nfgen_family: u8,
    pub version: u8,
    pub res_id: u16,
}

impl NfGenMsg {
    fn new_ipv4(queue_id: u16) -> NfGenMsg {
        NfGenMsg {
            nfgen_family: NFPROTO_IPV4 as u8,
            version: NFNETLINK_V0 as u8,
            res_id: queue_id.to_be(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NfqNlMsgConfigCmd {
    pub command: u8,
    pub padding: u8,
    pub pf: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NlAttr {
    pub nla_len: u16,
    pub nla_ty: u16,
}

impl NlAttr {
    fn new_with_command(len: u16, command: u16) -> NlAttr {
        NlAttr {
            nla_len: len,
            nla_ty: command,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct NfqNlMsgConfigParams {
    pub copy_range: u32,
    pub copy_mode: u8,
}

fn align_to_4(x: usize) -> usize {
    (x + 3) & !3
}

pub struct NlMsghdr {
    pub nh: nlmsghdr,
}

#[derive(Debug, Clone)]
pub enum NfnlPayload {
    NlmsgDone,
    NlmsgError {
        payload: nlmsgerr,
    },
    NlmsgNoop,
    NlmsgOverrun,
    NfqnlMsgPacket {
        queue_id: u16,
        packet_id: u32,
        hook: u8,
        payload: Vec<u8>,
    },
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NfqNlMsgVerdictHdr {
    verdict: u32,
    id: u32,
}

impl NlMsghdr {
    /**
    Initialize a nlmsghdr with default values for our usecases.
    Default flags: NLM_F_REQUEST | NLM_F_ACK
    Default type: (NFNL_SUBSYS_QUEUE << 8)
    **/
    fn new(ack: bool) -> NlMsghdr {
        let mut nh: nlmsghdr = unsafe { zeroed() };
        nh.nlmsg_pid = 0; // Kernel address
        nh.nlmsg_seq = 0;
        // NLM_F_REQUEST to actually perform stuffs, request an ack by setting the NLM_F_ACK flag
        nh.nlmsg_flags = (NLM_F_REQUEST | if ack { NLM_F_ACK } else { 0 }) as u16;
        nh.nlmsg_len = 0;
        nh.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) as u16; // We request for NFQNL_MSG_CONFIG, we will receive NFQNL_MSG_PACKETs

        NlMsghdr { nh }
    }

    fn add_type(&mut self, t: u16) {
        self.nh.nlmsg_type = self.nh.nlmsg_type | t;
    }

    fn set_len(&mut self, l: u32) {
        self.nh.nlmsg_len = l;
    }
}

fn build_message(sa: &mut sockaddr_nl, iovs: &mut Vec<iovec>) -> msghdr {
    msghdr {
        msg_name: sa as *mut _ as *mut c_void,
        msg_namelen: size_of::<sockaddr_nl>() as u32,
        msg_iov: iovs.as_mut_slice().as_mut_ptr(),
        msg_iovlen: iovs.len(),
        msg_control: null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    }
}

macro_rules! add_iov {
    ($iovs: expr, $obj: expr) => {
        $iovs.push(iovec {
            iov_base: $obj as *mut _ as *mut c_void,
            iov_len: std::mem::size_of_val($obj) as size_t,
        });
    };
}

pub struct Socket {
    socket: c_int,
    sa: sockaddr_nl,
}

pub enum Verdict {
    Drop,
    Accept,
}

macro_rules! expect_ack_ok {
    ($s: expr) => {{
        let pkt = $s.receive_packet()?;
        let (_ret_header, ret_payload) =
            pkt.first().ok_or_else(|| String::from("No ACK received"))?;
        match ret_payload {
            NfnlPayload::NlmsgError { payload } => {
                if payload.error != 0 {
                    return Err(format!("Received ACK is an error: {}", payload.error));
                }
            }
            _ => {
                return Err(String::from("Invalid ACK received"));
            }
        }
    }};
}

impl Socket {
    pub fn new() -> Socket {
        let socket = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) };
        if socket < 0 {
            panic!("Failed to create socket");
        }
        //let mut sock_name: sockaddr = unsafe { zeroed() };
        let mut sa: sockaddr_nl = unsafe { zeroed() }; // Socket address
        sa.nl_family = AF_NETLINK as sa_family_t;
        let s: socklen_t = socklen_t::from(size_of::<sockaddr_nl>() as u32);
        let ret = unsafe { bind(socket, &mut sa as *mut _ as *mut sockaddr, s) };
        if ret < 0 {
            panic!("Failed to bind socket ({})", errno::errno());
        }

        Socket { socket, sa }
    }

    pub fn bind(&mut self, queue_id: u16) -> Result<(), String> {
        {
            // Initialize
            let mut nh = NlMsghdr::new(true);
            nh.add_type(NFQNL_MSG_CONFIG as u16);
            nh.set_len(
                size_of::<nlmsghdr>() as u32
                    + size_of::<NfGenMsg>() as u32
                    + size_of::<NlAttr>() as u32
                    + size_of::<NfqNlMsgConfigCmd>() as u32,
            );

            let mut nfmsg = NfGenMsg::new_ipv4(queue_id);

            let mut attr = NlAttr::new_with_command(
                (size_of::<NlAttr>() + size_of::<NfqNlMsgConfigCmd>()) as u16,
                NFQA_CFG_CMD,
            );

            let mut cmd = NfqNlMsgConfigCmd {
                command: NFQNL_CFG_CMD_BIND,
                padding: 0,
                pf: (libc::AF_INET as u16).to_be(),
            };

            let mut iovs = Vec::new();
            add_iov!(iovs, &mut nh.nh);
            add_iov!(iovs, &mut nfmsg);
            add_iov!(iovs, &mut attr);
            add_iov!(iovs, &mut cmd);

            let msg = build_message(&mut self.sa, &mut iovs);

            let ret = unsafe { sendmsg(self.socket, &msg, 0) };
            if ret < 0 {
                return Err(String::from("Failed to send message"));
            }
            expect_ack_ok!(self);
        }
        {
            // Set params
            let orig_size = size_of::<nlmsghdr>()
                + size_of::<NfGenMsg>()
                + size_of::<NlAttr>()
                + size_of::<NfqNlMsgConfigParams>();
            let aligned_size = align_to_4(orig_size);

            let mut nh = NlMsghdr::new(true);
            nh.add_type(NFQNL_MSG_CONFIG as u16);
            nh.set_len(aligned_size as u32);

            let mut nfmsg = NfGenMsg::new_ipv4(queue_id);

            let mut attr = NlAttr::new_with_command(
                (size_of::<NlAttr>() + size_of::<NfqNlMsgConfigParams>()) as u16,
                NFQA_CFG_PARAMS as u16,
            );

            let mut cmd = NfqNlMsgConfigParams {
                copy_range: 65535u32.to_be(),
                copy_mode: NFQNL_COPY_PACKET as u8,
            };

            let mut iovs = Vec::new();
            add_iov!(iovs, &mut nh.nh);
            add_iov!(iovs, &mut nfmsg);
            add_iov!(iovs, &mut attr);
            add_iov!(iovs, &mut cmd);
            if aligned_size != orig_size {
                let mut pad = vec![0u8; aligned_size - orig_size];
                add_iov!(iovs, &mut pad);
            }

            let msg = build_message(&mut self.sa, &mut iovs);

            let ret = unsafe { sendmsg(self.socket, &msg, 0) };
            if ret < 0 {
                return Err(String::from("Failed to send message"));
            }
            expect_ack_ok!(self);
            Ok(())
        }
    }

    pub fn receive_packet(&mut self) -> Result<Vec<(NlMsghdr, NfnlPayload)>, String> {
        let mut ret = Vec::new();
        // Receive

        let mut rx_buf: Vec<u8> = vec![0u8; 65535];

        let mut rx_iov = iovec {
            // Memory region containing the message
            iov_base: rx_buf.as_mut_ptr() as *mut c_void,
            iov_len: rx_buf.len() as size_t,
        };

        let mut rx_msg: msghdr = unsafe { zeroed() };
        rx_msg.msg_iov = &mut rx_iov;
        rx_msg.msg_iovlen = 1;
        let ret_code = unsafe { recvmsg(self.socket, &mut rx_msg, 0) };
        if ret_code < 0 {
            return Err(String::from("Failed to receive message"));
        }

        let mut offset = 0;

        while offset + size_of::<nlmsghdr>() < ret_code as usize {
            let header: nlmsghdr =
                unsafe { ptr::read_unaligned(rx_buf[offset..].as_mut_ptr() as _) };

            let nlmsg_len = header.nlmsg_len as usize;
            let payload = rx_buf[offset + size_of::<nlmsghdr>()..offset + nlmsg_len].to_vec();

            // Netlink messages are aligned to 4-byte boundaries.
            let aligned_len = align_to_4(header.nlmsg_len as usize);
            offset += aligned_len;

            let parsed_payload = match header.nlmsg_type.to_le() {
                0x1 => NfnlPayload::NlmsgNoop,
                0x2 => NfnlPayload::NlmsgError {
                    payload: unsafe { ptr::read_unaligned(payload.as_ptr() as _) },
                },
                0x3 => NfnlPayload::NlmsgDone,
                0x4 => NfnlPayload::NlmsgOverrun,
                0x300 => {
                    let nf_gen_msg: NfGenMsg =
                        unsafe { ptr::read_unaligned(payload[..4].as_ptr() as _) };

                    let queue_id = u16::from_be(nf_gen_msg.res_id);
                    let mut packet_id = 0u32;
                    let mut hook = 0u8; // Hook is the point where the packet was captured (3 -> OUTPUT)
                    //let mut ip_payload: Vec<u8> = Vec::new();

                    let mut offset = size_of::<NfGenMsg>();
                    while offset + size_of::<NlAttr>() <= payload.len() {
                        let nl_attr: NlAttr = unsafe {
                            ptr::read_unaligned(
                                payload[offset..offset + size_of::<NlAttr>()].as_ptr() as _,
                            )
                        };
                        let len = nl_attr.nla_len as usize;
                        if len < size_of::<NlAttr>() || offset + len > payload.len() {
                            break;
                        }
                        let data = &payload[offset + size_of::<NlAttr>()..offset + len];

                        match nl_attr.nla_ty & 0x3fff {
                            1 if data.len() >= 7 => {
                                packet_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
                                hook = data[6];
                            }
                            10 => {
                                //ip_payload = data.to_vec();
                            }
                            _ => {
                                panic!("Unexpected")
                            }
                        }

                        offset += size_of::<NlAttr>() + len;
                    }
                    NfnlPayload::NfqnlMsgPacket {
                        queue_id,
                        packet_id,
                        hook,
                        payload: payload.clone().drain(4 + size_of::<NlAttr>()..).collect(),
                    }
                }
                _ => {
                    return Err(format!(
                        "Unsupported nlmsg type: {}",
                        header.nlmsg_type.to_le()
                    ));
                }
            };

            ret.push((NlMsghdr { nh: header }, parsed_payload));
        }

        Ok(ret)
    }

    pub fn verdict(
        &mut self,
        queue_id: u16,
        packet_id: u32,
        verdict: Verdict,
    ) -> Result<(), String> {
        let size = size_of::<nlmsghdr>()
            + size_of::<NfGenMsg>()
            + size_of::<NlAttr>()
            + size_of::<NfqNlMsgVerdictHdr>();

        let mut nh = NlMsghdr::new(false);
        nh.add_type(NFQNL_MSG_VERDICT as u16);
        nh.set_len(size as u32);

        let mut nfmsg = NfGenMsg::new_ipv4(queue_id);

        let mut attr = NlAttr::new_with_command(
            (size_of::<NlAttr>() + size_of::<NfqNlMsgVerdictHdr>()) as u16,
            NFQA_VERDICT_HDR as u16,
        );

        let mut vh = NfqNlMsgVerdictHdr {
            verdict: match verdict {
                Verdict::Drop => 0u32,
                Verdict::Accept => 1u32,
            }
            .to_be(),
            id: packet_id.to_be(),
        };

        let mut iovs = Vec::new();
        add_iov!(iovs, &mut nh.nh);
        add_iov!(iovs, &mut nfmsg);
        add_iov!(iovs, &mut attr);
        add_iov!(iovs, &mut vh);

        let msg = build_message(&mut self.sa, &mut iovs);

        let ret = unsafe { sendmsg(self.socket, &msg, 0) };
        if ret < 0 {
            return Err(String::from("Failed to send message"));
        }
        Ok(())
    }
}
