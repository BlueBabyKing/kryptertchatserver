package yes;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    private final ServerSocket serverSocket;

    public static void main(String[] args) throws IOException {
    ServerSocket serverSocket = new ServerSocket(22222);
    Server server = new Server(serverSocket);
    server.startServer();
    }

    public Server(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }

    public void startServer(){
        System.out.println("Server Successfully Started");
        try{
            while(!serverSocket.isClosed()){
                Socket socket = serverSocket.accept();

                ClientHandler clientHandler = new ClientHandler(socket);
                System.out.println("A Client("+ clientHandler.getClientUserName() +") Connected to The Server");
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        }catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
