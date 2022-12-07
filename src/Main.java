import java.math.BigInteger;
import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        RSA rsa = new RSA();

        Scanner myObj = new Scanner(System.in);
        System.out.println("Insira o texto a ser encriptado");

        String plainText = myObj.nextLine();
        System.out.println("Texto puro: " + plainText);

        List<BigInteger> encrypted = rsa.encrypt(plainText);

        System.out.println("Lista de valores encriptados: " + encrypted);

        String decryptedResult = rsa.decrypt(encrypted);
        System.out.println("Decriptado: " + decryptedResult);
    }
}