signature dpd_Radius_client {
    ip-proto == udp
    payload /^\x01/
}

signature dpd_Radius_server {
    ip-proto == udp
    payload /^(\x02|\x03|\x11)/
    requires-reverse-signature dpd_Radius_client
    enable "spicy_Radius"
}
