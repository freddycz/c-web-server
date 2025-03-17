# c-web-server
Simple web server written in C that responds to GET requests and serves static files from a specified directory. 

## Motivation
This project was created to deepen my understanding of how HTTP works under the hood and to learn the basics of network programming. I wanted to explore how web servers handle client requests and responses at a low level.

## Disclaimer
This server only implements response handling for GET requests and ignores HTTP headers. It is a learning experimental project, and not intended for production use.

## Usage guide 

### Running the server 
1. run ```make``` to compile the code.
2. start the server by executing: ```./build/main```

### Configuration
To change the port or target directory, modify the arguments in the following function call:
```c
new_server(char *port, char *target_dir);
```

For example, in ```main.c```, you can configure the server to listen on port ```3000``` and serve files from the ```web``` directory like this:
```c
new_server("3000", "web");
```
This will run the web server on port 3000 and server Bezdinek web as an example.
