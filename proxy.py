import sys
import socket
import threading

#####contains ASCII-printable chars, if one exits, or a dot (.) if such a representation doesn't exist
HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])   #if len(repr(chr(i))) == 3 print i, otherwise, print '.'

#####hedump function that takes some input as bytes or a string and prints a hexdump to the console. Will output packet details in hexadecimal and ASCII-printable chars
def hexdump(src, length=16, show=True):     
    if isinstance(src, bytes):      #we make sure we have a string, decoding the bytes if a byte string was passed in
        src = src.decode()

    results = list()
    for i in range(0, len(src), length):
        word = str(src[i:i+length])     #we grab a piece of the string to dump and put it into the word variable
       
        printable = word.translate(HEX_FILTER)       #we use the translate built-in func to substitute the str representation of each char for printable string
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')   #we create a new array to hold the strings, result, that conatins the hex value of the index of 
                                                                    #the first byte in the word, the hex value of the word, and its printable representation
    if show:
        for line in results:
            print(line)
    else:
        return results

def receive_from(connection):
    buffer = b""
    connection.settimeout(5)        #we create an empty byte string, buffer, that will accumulate responses from the socket
    try:
        while True:
            data = connection.recv(4096)    #we set  up a loop to read response data data into the buffer until there's no more data or we time out
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer

def request_handler(buffer):
    #perform packet modifications
    return buffer

def response_handler(buffer):
    #perform packet modifications
    return buffer

#####proxy handler function
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))           #we connect to the remote host

    if receive_first:                                   #we check to make sure we dont need to first initiate a connection to the remote side and request data before
        remote_buffer = receive_from(remote_socket)     #going into the main loop
        hexdump(remote_buffer)
    
    remote_buffer = response_handler(remote_buffer)     #we hand the output to the response_handler function and then send the received buffer to the local client
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)
    
    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[==>]Received %d bytes form localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Send to remote.")

        remote_buffer= receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received &d bytes form remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Send to localhost.")

        if not len(local_buffer) or not len(remote_buffer):     #when theres no data to send on either side of the communication, we close both the local and remote
            client_socket.close()                               #sockets and break out of the loop
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break

#####server loop function
def server_loop(local_host, local_port,
                remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #the server_loop function creates a socket
    try:
        server.bind((local_host, local_host))   #the server_loop then binds to to the local host and listens
    except Exception as e:
        print('problem on bind: %r' % e)

        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)
    
    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)
    while True:                                                     #main loop
        client_socket, addr = server.accept()
        # print out the local connection information
        line = "> Received incoming connection from %s:%d" % (addr[0], addr[1])
        print(line)
        #start a thread to talk to the remote host
        proxy_thread = threading.Thread(                            #when a fresh connection request comes in, we hand it off to the proxy_handler in a new thread,
            target=proxy_handler,                                   #which does all of the sending and receiving of juicy bits to either side of the data stream
            args=(client_socket, remote_host,
            remote_port, receive_first))
        proxy_thread.start()

#####main function
def main():                             #in the main function, we take in some command line arguments and then fire up the server loop that listens for connections
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport]", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    server_loop(local_host, local_port, 
        remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()