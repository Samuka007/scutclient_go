# scut authentication logic

## Total 

### Sent logoff twice

- sent logoff package on eap layer    
- handle error response if neccesary

### Sent start package

- sent start package to multicast endpoint on eap layer
- check response 
    - if response and receive
        - set server mac
        - handle response pkg in [eap handler](#8021x-handler)
    - else sent to multi endpoint if broad / sent to broad endpoint if multi

### Start heart beat handle

- listen socket
    - if 802.1x receive failure -> error
    - if receive -> [handle udp](#udp-handler)

- if neet heart beat
    - if too late -> recall
    - else -> sent heart beat pkt and reset hb pkt

## 802.1X handler

### FAILURE

- retry or exit

### Request

- identity
- MD5 challenge
- notification
- others

### SUCCESS

- Drcom_MISC_START_ALIVE

## udp handler

### receive_data start with 0x07

- misc response for alive
- misc response info
- misc heart beat
    - check heart beat type and send
- misc response heart beat
    - send heart beat type 1

### receive data start with 0x4d38

- receive server information and log
