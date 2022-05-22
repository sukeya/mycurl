import argparse
import base64
import functools
from pathlib import Path
import re
import socket
import ssl
import sys
from typing import Tuple, Union, Iterable
from urllib import parse as urlparse


def extract_host_and_port(url: str):
    """
    extract the host and port from url
    :param url: URL
    :return: host name, port number
    """
    parsed_url = urlparse.urlparse(url)
    if parsed_url.port is not None:
        port = parsed_url.port
    else:
        # even if scheme is None, substitute it for port
        port = parsed_url.scheme
    return parsed_url.hostname, port


class ProxyConnection:
    """
    This class represents a connection through a proxy server.
    """
    def __init__(
            self,
            url: str,
            connect_timeout: float,
            candidates_of_proxy_address: Iterable[Union[Tuple[str, int], Tuple[str, int, int, int]]]
    ):
        """
        :param url: URL
        :param connect_timeout: after this time passes, this connection will be closed.
        :param candidates_of_proxy_address: candidates of proxy server's address.
        """
        self.url = url
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(connect_timeout)
        for address in candidates_of_proxy_address:
            try:
                self.sock.connect(address)
                break
            except OSError:
                pass
        else:
            raise ValueError("Invalid addresses.")

    def send(self, data) -> int:
        return self.sock.send(data)

    def recv(self, buffer_size: int) -> bytes:
        return self.sock.recv(buffer_size)

    def shutdown(self, how: int) -> None:
        self.sock.shutdown(how)

    def __del__(self):
        self.sock.close()


class Connection:
    """
    This class represents a connection.
    """
    def __init__(self, url: str, connect_timeout: float):
        """
        :param url: URL
        :param connect_timeout:
        """
        hostname, port = extract_host_and_port(url)
        host_addresses = socket.getaddrinfo(host=hostname, port=port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(connect_timeout)
        for address in host_addresses:
            try:
                self.sock.connect(address[-1])
                break
            except OSError:
                pass
        else:
            raise ValueError("Invalid addresses.")

    def send(self, data) -> int:
        return self.sock.send(data)

    def recv(self, buffer_size: int) -> bytes:
        return self.sock.recv(buffer_size)

    def shutdown(self, how: int) -> None:
        self.sock.shutdown(how)

    def __del__(self):
        self.sock.close()


class TLSConnection:
    def __init__(self, url: str, connect_timeout: float):
        """
        :param url: URL
        :param connect_timeout:
        """
        hostname, port = extract_host_and_port(url)
        host_addresses = socket.getaddrinfo(host=hostname, port=port)

        context = ssl.create_default_context()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.sock.settimeout(connect_timeout)
        self.ssock = context.wrap_socket(self.sock, server_hostname=hostname)
        for address in host_addresses:
            try:
                self.ssock.connect(address[-1])
                break
            except ssl.SSLError:
                pass
        else:
            raise ValueError("Invalid addresses.")

    def send(self, data) -> int:
        return self.ssock.send(data)

    def recv(self, buffer_size: int) -> bytes:
        return self.ssock.recv(buffer_size)

    def shutdown(self, how: int) -> None:
        self.ssock.shutdown(how)

    def __del__(self):
        self.ssock.close()
        self.sock.close()


class ProxyConnectionMaker:
    """
    a class which make ProxyConnections.
    """
    def __init__(self, proxy_server_url: str):
        """
        :param proxy_server_url: the URL of proxy server
        """
        hostname, port = extract_host_and_port(proxy_server_url)
        # resolve IP address of proxy server.
        self.proxy_host_addresses = socket.getaddrinfo(host=hostname, port=port)

    def establish_connection(self, url: str, connect_timeout: float):
        """
        return a connection through proxy which have send, recv, shutdown method.
        :param url: URL
        :param connect_timeout: after this time passes, this connection will be closed.
        :return: a connection through proxy
        """
        return ProxyConnection(url, connect_timeout, (proxy_address[-1] for proxy_address in self.proxy_host_addresses))


def make_request(url: str) -> bytes:
    """
    return a request to url.
    :param url: URL
    :return: a request to url
    """
    parsed_url = urlparse.urlparse(url)
    return "\r\n".join([
        f"GET {parsed_url.path} HTTP/1.1",
        f"HOST: {parsed_url.hostname}",
        "User-Agent: curl",
        "Accept: */*",
        "\r\n"
    ]).encode()


def make_request_in_http2(url: str) -> bytes:
    """
    return a request to url.
    :param url: URL
    :return: a request to url
    """
    parsed_url = urlparse.urlparse(url)
    return "\r\n".join([
        f"GET {parsed_url.path} HTTP/2",
        f"HOST: {parsed_url.hostname}",
        "User-Agent: curl",
        "Accept: */*",
        "\r\n"
    ]).encode()


def make_request_through_proxy(url: str, proxy_user: str) -> bytes:
    """
    return a request to url through proxy.
    :param url: URL
    :param proxy_user: BASIC authentication for proxy.
    :return: a request to url through proxy
    """
    return "\r\n".join([
        f"GET {url} HTTP/1.1",
        "Proxy-Authorization: Basic " + base64.b64encode(proxy_user.encode()).decode("ASCII"),
        "User-Agent: curl",
        "Accept: */*",
        "Proxy-Connection: Keep-Alive",
        "\r\n"
    ]).encode()


def get_html(url: str, connect_timeout: float, establish_connection, make_request) -> str:
    """
    return the HTML file located at url
    :param url: URL
    :param connect_timeout: after this time passes, this connection will be closed.
    :param establish_connection: a func which return a connection when it is given a URL and a connection timeout.
    :param make_request: a func which return a request when it is given a URL.
    :return: the content of HTML file
    """
    parsed_url = urlparse.urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise RuntimeError("Sorry, I support only http(s).")
    connection = establish_connection(url, connect_timeout)
    request = make_request(url)
    # send request
    total_sent_bytes = 0
    while total_sent_bytes < len(request):
        sent_bytes = connection.send(request[total_sent_bytes:])
        if sent_bytes == 0:
            raise RuntimeError("Socket connection broken")
        total_sent_bytes += sent_bytes
    connection.shutdown(socket.SHUT_WR)

    # receive response
    # at first, receive http header.
    header = dict()
    remainder = b""
    while True:
        header_chunk = connection.recv(4096)
        if header_chunk == b"":
            raise RuntimeError("Invalid HTTP header.")
        # add remainder which is that of previous loop to header chunk
        # this may cause large memory allocation, but I allow it because I believe http header is small.
        header_chunk = remainder + header_chunk
        # separate the first line with the other because it doesn't contain ":".
        if len(header) == 0 and header_chunk.find(b"\r\n") != -1:
            header["status"], header_chunk = header_chunk.split(b"\r\n", maxsplit=1)
            header["status"] = header["status"].decode()
        # get http tag and its value
        while header_chunk.find(b":") != -1 and header_chunk.find(b"\r\n") != -1:
            if header_chunk.find(b":") > header_chunk.find(b"\r\n"):
                break
            tag, header_chunk = header_chunk.split(b":", maxsplit=1)
            # decode binary representation
            tag = tag.decode()
            header[tag], header_chunk = header_chunk.split(b"\r\n", maxsplit=1)
            header[tag] = header[tag].decode().strip()
        # bind remainder which is needed for next loop.
        remainder = header_chunk
        # check if http header ends
        if header_chunk.startswith(b"\r\n"):
            break

    # a list which is added message body to
    chunks = []
    if "Content-Length" in header.keys():
        # remove "\r\n" at the head.
        chunks.append(remainder[2:])
        msg_body_size = int(header["Content-Length"])
        received_bytes = len(chunks[0])
        while received_bytes < msg_body_size:
            chunk = connection.recv(4096)
            if chunk == b'':
                break
            chunks.append(chunk)
            received_bytes += len(chunk)
    elif "Transfer-Encoding" in header.keys() and header["Transfer-Encoding"] == "chunked":
        chunk_len_pattern = re.compile(rb"\r\n[\da-fA-F]+\r\n")
        chunk = b""
        # this flag is needed for checking if message body ends.
        found_zero = False
        while True:
            # this may cause large memory allocation,
            # but I allow it because it is difficult for me to address the border of bytes.
            chunk = remainder + chunk
            chunk_len_matches = tuple(re.finditer(chunk_len_pattern, chunk))
            if len(chunk_len_matches) == 0:
                # move chunk to remainder because no mark of the beginning of chunk exists.
                remainder = chunk
            else:
                for chunk_len_match in chunk_len_matches:
                    # get the length of chunk
                    chunk_len = int(chunk_len_match.group(0).strip(), base=16)
                    if chunk_len == 0:
                        found_zero = True
                        break
                    # check if a chunk is included.
                    if len(chunk) - chunk_len_match.end() + 1 >= chunk_len:
                        chunks.append(chunk[chunk_len_match.end(): chunk_len_match.end() + chunk_len])
                        remainder = chunk[chunk_len_match.end() + chunk_len:]
                    else:
                        # this chunk continues another packet.
                        remainder = chunk[chunk_len_match.start():]
                        break
            if found_zero:
                break
            chunk = connection.recv(4096)
            if chunk == b'':
                break
    else:
        raise RuntimeError("Unknown length of message body.")

    # check the character encoding
    encoding = ""
    if "Content-Encoding" in header.keys():
        encoding = header["Content-Encoding"]
    elif "Content-Type" in header.keys() and header["Content-Type"].find("charset") != -1:
        for elem in header["Content-Type"].split(";"):
            if elem.find("charset=") != -1:
                encoding = elem[elem.find("charset=") + 8:]
                break
    else:
        raise RuntimeError("Not found any character encoding.")
    return b''.join(chunks).decode(encoding)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url", metavar="URL", type=str,
                        help="Specify an URL.")
    parser.add_argument("-u", "--proxy-user", metavar="<user:password>", type=str, default=None,
                        help="Specify the user name and password to use for proxy authentication.")
    parser.add_argument("-x", "--proxy", metavar="[protocol://]host[:port]", type=str, default=None,
                        help="Use the specified proxy.")
    parser.add_argument("--connect-timeout", metavar="<fractional seconds>", type=float,  default=90.0,
                        help="Maximum time in seconds that you allow curl's connection to take.")
    parser.add_argument("-o", "--output", metavar="<file>", type=Path, default=None,
                        help="Write output to <file> instead of stdout.")
    args = parser.parse_args()

    if args.proxy is not None and args.proxy_user is not None:
        if args.proxy.find("://") == "-1":
            proxy = "http://" + args.proxy
        else:
            proxy = args.proxy
        maker = ProxyConnectionMaker(proxy)
        get = functools.partial(
            get_html,
            establish_connection=lambda url, timeout: maker.establish_connection(url, timeout),
            make_request=lambda url: make_request_through_proxy(url, args.proxy_user)
        )
    elif args.proxy is None and args.proxy_user is None:
        parsed_url = urlparse.urlparse(args.url)
        if parsed_url.scheme == "http":
            get = functools.partial(
                get_html,
                establish_connection=lambda url, connect_timeout: Connection(url, connect_timeout),
                make_request=make_request
            )
        elif parsed_url.scheme == "https":
            # get = functools.partial(
            #     get_html,
            #     establish_connection=lambda url, connect_timeout: TLSConnection(url, connect_timeout),
            #     make_request=make_request_in_http2
            # )
            raise RuntimeError("Sorry, I support only http.")
        else:
            raise RuntimeError("Sorry, I support only http.")
    else:
        raise ValueError("'--proxy' or '--proxy-user' not specified.")
    html = get(args.url, args.connect_timeout)
    # write the received HTML file.
    if args.output is not None:
        with open(args.output, mode="w", encoding="utf-8") as f:
            f.write(html)
    else:
        print(html)
