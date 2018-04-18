package com.example.progassign2;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServerWithSecurity {

	static PrivateKey privateKey;

	private static int port = 4600;

	private static Signature signature;

	public static void main(String[] args) {
		if (args.length > 0) port = Integer.parseInt(args[0]);
		init();

		ServerSocket welcomeSocket = null;
		Handler handler;
		int client_no = 0;

		try {
			welcomeSocket = new ServerSocket(port);
			System.out.println("Server started on port: " + port);
		} catch (IOException e) {
			e.printStackTrace();
		}

		System.out.println("Listening on main thread.....");
		while(true) {
			try {

				if (welcomeSocket != null) {
					final Socket welsoc = welcomeSocket.accept();

					handler = new Handler(welsoc, signature, client_no);
					handler.start();
					handler.join();
					break;
				}

			} catch (NullPointerException | IOException | InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	private static void init()  {
		try {
			String keyPath = "pricateServer.der";
			File privKeyFile = new File(keyPath);

			BufferedInputStream bis;

			try {
				bis = new BufferedInputStream(new FileInputStream(privKeyFile));
			} catch(FileNotFoundException e) {
				throw new Exception("Could not locate key file at '" + keyPath + "'", e);
			}

			int keyLen = (int) privKeyFile.length();
			byte[] privKeyBytes = new byte[keyLen];

			bis.read(privKeyBytes);
			bis.close();

			KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(ks);

			signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKey);

			System.out.println("Completed initialization.....");

		} catch (NoSuchAlgorithmException e) {
			System.out.println("No such Algorithm");
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.out.println("No such Padding");
			e.printStackTrace();
		} catch (Exception e)  {
			System.out.println("Exception caught");
			e.printStackTrace();
		}
	}

	private static class Handler extends Thread {
		Socket socket;
		Signature signature;
		int client;
		SecretKey Sec;

		PacketObj packet;
		Object obj;
		Packet type;
		int length;
		byte[] message;

		ObjectOutputStream toClient = null;
		ObjectInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		Handler(Socket socket, Signature signature, int client) {
			this.socket = socket;
			this.client = client;
			this.signature = signature;
		}

		private static byte[] decrypt(byte[] encryptedtext) {
			try {
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				return cipher.doFinal(encryptedtext);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return null;
		}

		static SecretKey decryptAESKey(byte[] aesEncrypted, Key privateKey){
			try {
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				SecretKey k = new SecretKeySpec(cipher.doFinal(aesEncrypted), "AES");
				return k;

			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}

			return null;
		}

		byte[] decryptCP2(byte[] plaintext, SecretKey key) {
			try {
				Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, key);
				return cipher.doFinal(plaintext);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}

			return null;
		}

		public void run() {
			try {
				fromClient = new ObjectInputStream(socket.getInputStream());
				toClient = new ObjectOutputStream(socket.getOutputStream());

				while (!socket.isClosed()) {

					obj = fromClient.readObject();
					if (obj instanceof PacketObj) {
						packet = (PacketObj) obj;
					}
					type = packet.getType();
					length = packet.getLength();
					message = packet.getMessage();

					switch(type) {
						case HELLO_SERVER:
							System.out.println("\nReceived hello message from client");

							if(Arrays.equals(message, Strings.HELLO_MESSAGE.getBytes("UTF-8"))) {
								System.out.println("Sending welcome message signed with private key.......");

								signature.update(Strings.WELCOME_MESSAGE.getBytes("UTF-8"));

								byte[] welcome_message = signature.sign();
								toClient.writeObject(new PacketObj(Packet.WELCOME,welcome_message.length,welcome_message));
								toClient.flush();
							}

							break;

						case REQ_CA_CERT:
							System.out.println("\nReceived request from client for certificate signed by CA");
							System.out.println("Responding appropriately.....");

							File cert = new File("server.crt");

							FileInputStream fileInputStream = new FileInputStream(cert);

							BufferedInputStream bis1 = new BufferedInputStream(fileInputStream);

							byte [] fromFileBuffer = new byte[(int) cert.length()];

							bis1.read(fromFileBuffer);

							toClient.writeObject(new PacketObj(Packet.SERVER_CERT, fromFileBuffer.length, fromFileBuffer));
							toClient.flush();

							System.out.println("Certificate has been sent!!");

							break;

						case FILE_NAME:
							System.out.println("Receiving file name");
							System.out.println("Incoming file: "+ new String(packet.getMessage(), 0, packet.getLength()));

							fileOutputStream = new FileOutputStream("../" + new String(message, 0, length));
							bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
							break;

						case FILE_BLOCK:

							byte[] decryp = decrypt(message);
							if (decryp != null) {
								bufferedFileOutputStream.write(decryp, 0, packet.getLength());
							}
							break;

						case NONCE:
							//read encrypted nonce
							toClient.writeObject(new PacketObj(Packet.NONCE, length, message));
							break;

						case AES_CP2_ENCRYPT:
							Sec = decryptAESKey(message, privateKey);
							break;

						case CP2_ENCRYPTED_FILE:
							byte[] decrypcp2 = decryptCP2(message, Sec);
							if (decrypcp2 != null) {
								bufferedFileOutputStream.write(decrypcp2, 0, packet.getLength());
							}
							break;

						case END:
							System.out.println("Closing socket");

							bufferedFileOutputStream.flush();

							socket.close();
							this.interrupt();
							break;
					}
				}
			} catch ( SignatureException | IOException | ClassNotFoundException e) {
				e.printStackTrace();
				System.exit(-1);
			}
		}
	}
}
