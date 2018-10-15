# Email Verifier

Email `Verifier` provides a verification of email deliverablity and existance 
over SOCKS proxy SMTP connection or normal SMTP connection.

Email Verifier uses the custom `SocksSMTP` class which is a subclass of builtin SMTP class and 
replaces the socket attribute with SOCKS proxy sockets if a proxy is provided.
The class acts as normal SMTP in case no proxy is provided.


## How is email verified?

The best way to test deliverablity of an email address will be to actually
send an email. But, we don't want to spam anyone's email just to test that.

Next best thing will be to try sending an email but close the connection just before completing the process.

Here are the steps how we do that.

1. Create a connection with the SMTP sever for the given email (Provided the email is in valid format).
2. Send `HELO` to initialize the conversation with the server.
3. Send `MAIL FROM` to indicate the sender's address.
4. Send `RCPT TO` with the email address to verify.
5. Determine the deliverablity of the email based on the status of `RCPT TO`.
6. Close the connection.

## Example Usage

Copy the verifier directory to your project

```python
# use an appropriate path to import
from verifier.verifier import Verifier

# Use normal SMTP to connect to the server
normal_verifier = Verifier(source_addr='user@example.com') # No proxy
results = normal_verifier.verify('myemail@example.com')

# Use socks proxy to connect over SMTP
socks_verifier =  Verifier(
    source_addr='user@example.com',
    proxy_type='socks5',
    proxy_addr='socks5.your-proxy-provider.com',
    proxy_port=1080,
    proxy_username='funky-username',
    proxy_password='crazy-password'
)
results = socks_verifier.verify('myemail@example.com')
```

The verifier can also be run directly.

```bash
$ python3 verifier.py
```

> Make sure your firewall allows outgoing connects on SMTP port.

## Dependencies

This project have following external dependencies

- [PySocks](https://github.com/Anorov/PySocks) for SOCKS enabled sockets
- [dnspython](http://www.dnspython.org/) for DNS lookup

## Contributions

I you find any bugs, please feel free to open an issue or send a pull request.

