all : server client

server : B023040001_server.o cubelib.o
	gcc -o server B023040001_server.o cubelib.o

client : B023040001_client.o cubelib.o
	gcc -o client B023040001_client.o cubelib.o -l pthread

B023040001_server.o : B023040001_server.c cubelib.o
	gcc -c B023040001_server.c 

B023040001_client.o : B023040001_client.c cubelib.o
	gcc -c B023040001_client.c 

cubelib.o : cubelib.c cubelib.h
	gcc -c cubelib.c 
clear : 
	rm -f *.o server client rcv_* data recv_data
