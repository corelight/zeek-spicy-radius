module Radius;

export {
    redef enum Log::ID += { RADIUS_LOG };

    type Info: record {
		## Time
		ts: time &log &default=network_time();

		## Unique ID for the connection
		uid: string &log;

		## The connection's 4-tuple of endpoint addresses/ports
		id: conn_id &log;

        ## Transport protocol
        proto: transport_proto &log;

        ## Username
        username: string &log &optional;

        ## NAS IP Addr
        nas_ip_addr: addr &log &optional;

        ## NAS IP Addr
        nas_port: count &log &optional;

        ## Framed IP Addr
        framed_ip_addr: addr &log &optional;

        ## Framed IP netmask
        framed_ip_netmask: addr &log &optional;

        ## Set to True if an Access-Accpet was seen
        success: bool &log &default=F;
    };

    ### Events ###

    global Radius::message: event(c: connection, is_orig: bool, 
                                       code: zeek_spicy_radius::CodeType,
                                       id: count);

    global Radius::attribval: event(c: connection, is_orig: bool, 
                                    r_type: count, value: string);

    # Log event
    global Radius::log_radius: event(rec: Radius::Info);
}

redef record connection += {
	spicy_radius: Radius::Info &optional;
};

const code_type = {
    [zeek_spicy_radius::CodeType_ACCESS_REQUEST] = "Access-Request",
    [zeek_spicy_radius::CodeType_ACCESS_ACCEPT] = "Access-Accept",
    [zeek_spicy_radius::CodeType_ACCESS_REJECT] = "Access-Reject",
    [zeek_spicy_radius::CodeType_ACCOUNTING_REQUEST] = "Accounting-Request",
    [zeek_spicy_radius::CodeType_ACCOUNTING_RESPONSE] = "Accounting-Response",
    [zeek_spicy_radius::CodeType_ACCESS_CHALLENGE] = "Access-Challenge",
    [zeek_spicy_radius::CodeType_STATUS_SERVER] = "Status-Server",
    [zeek_spicy_radius::CodeType_STATUS_CLIENT] = "Status-Client",
    [zeek_spicy_radius::CodeType_RESERVED] = "Reserved",
} &default = function(n: zeek_spicy_radius::CodeType): 
                        string { return fmt("unk-%s", n); };

function set_session(c: connection)
    {
    if ( ! c?$spicy_radius )
        {
        c$spicy_radius = [$uid=c$uid, $id=c$id, $proto=get_conn_transport_proto(c$id)];
        }
    }

event Radius::message(c: connection, is_orig: bool, 
                      code: zeek_spicy_radius::CodeType,
                      id: count)
    {
    set_session(c);
    if (code == zeek_spicy_radius::CodeType_ACCESS_ACCEPT)
        c$spicy_radius$success = T;
    }

event Radius::attribval(c: connection, is_orig: bool, 
                        r_type: count, value: string)
    {
    switch r_type {
        case 1:
            set_session(c);
            c$spicy_radius$username = value;
            break;
        case 4:
            set_session(c);
            c$spicy_radius$nas_ip_addr = raw_bytes_to_v4_addr(value);
            break;
        case 5:
            set_session(c);
            c$spicy_radius$nas_port = bytestring_to_count(value);
            break;
        case 8:
            set_session(c);
            c$spicy_radius$framed_ip_addr = raw_bytes_to_v4_addr(value);
            break;
        case 9:
            set_session(c);
            c$spicy_radius$framed_ip_netmask = raw_bytes_to_v4_addr(value);
            break;
        default:
            break;
        }
    }

event connection_state_remove(c: connection)
    {
    if (c?$spicy_radius)
        Log::write(Radius::RADIUS_LOG, c$spicy_radius);
    }

event zeek_init() &priority=5 
    {
    Log::create_stream(Radius::RADIUS_LOG, 
                [$columns=Info, $ev=log_radius, $path="radius"]);
    }