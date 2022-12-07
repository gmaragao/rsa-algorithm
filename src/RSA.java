import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class RSA {
    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger n;
    private BigInteger phi;
    public RSA () {
        int bitLength = 1024;

        Random random = new Random();

        // 1º passo -- definir 2 números primos grandes
        BigInteger bigPrime1 = BigInteger.probablePrime(bitLength, random);
        BigInteger bigPrime2 = BigInteger.probablePrime(bitLength, random);

        // Confere se numeros sao diferentes
        while(bigPrime1.compareTo(bigPrime2) == 0) {
            bigPrime2 = BigInteger.probablePrime(bitLength, random);
        }

        // 2º passo -- calcular n e phi que serão utilizados para encriptar e desencriptar
        n = bigPrime1.multiply(bigPrime2);
        phi = (bigPrime1.subtract(BigInteger.ONE)).multiply(bigPrime2.subtract(BigInteger.ONE));

        // 3º passo -- achar um valor primo relativo a phi (coprimo) para ser uma das cahves
        // Acha coprimo para gerar chave
        publicKey = findCoprime(phi);

        // 4º passo -- calcular o modulo inverso entre a chave anteriormente gerada e phi
        privateKey = publicKey.modInverse(phi);

    }

    /*
     * Calcula o maior divisor comum a partir do algoritmo euclidiano
     * */
    static BigInteger gcd(BigInteger a, BigInteger b)
    {
        // Igual a zero
        if (a.compareTo(BigInteger.ZERO) == 0)
            return b;

        return gcd(b.mod(a), a);
    }


    private List<Integer> convertStringToAscii(String givenString) {
        List<Integer> asciiChars = new ArrayList<>();
        for (char ch : givenString.toCharArray()) {
            int asciiValue = ch;
            asciiChars.add(asciiValue);
        }

        return asciiChars;
    }


    private BigInteger findCoprime(BigInteger primeNumber) {
        Random random = new Random();

        // Inicia com um primo com tamanho relativamente menor
        BigInteger coprime = BigInteger.probablePrime(primeNumber.bitLength() / 2, random);

        // Busca o maior divisor comum entre "e" e "phi"
        // O MDC/GCD precisa ser igual a 1 (para ser primo) e "e" precisa ser menor que phi
        // Assim encontrando um valor para "e" que seja coprimo de "phi"
        while (gcd(coprime, primeNumber).compareTo(BigInteger.ONE) == 1 && coprime.compareTo(primeNumber) == -1)
        {
            coprime = coprime.add(BigInteger.ONE);
        }

        return coprime;
    }

    // Neste caso usaremos a chave publica para encriptar e a chave privada para desencriptar
    // O algoritmo pode usar as chaves de maneira inversa tambem

    // Transforma uma string a ser encriptada em numeros a partir de conversao ASCII
    // Gera uma lista de valores a partir do calculo de encriptacao de RSA P^e (mod n)

    public List<BigInteger> encrypt (String givenText) {
        List<Integer> asciiNumbers = convertStringToAscii(givenText);

        return encryptAsciiNumbers(asciiNumbers);
    }

    /**
     * Recebe uma lista de inteiros e retorna seus valores calculados pela fórmula de encriptação
     * @param asciiNumbers chars transformados em ascii
     * @return List<BigInteger> valores calculados com formula de encriptação
     */
    private List<BigInteger> encryptAsciiNumbers (List<Integer> asciiNumbers) {
        List<BigInteger> encryptedResult = new ArrayList<>();

        for (int asciiChar : asciiNumbers) {
            BigInteger asciiBigInt = BigInteger.valueOf(asciiChar);
            BigInteger encryptedChar = asciiBigInt.modPow(publicKey, n);
            encryptedResult.add(encryptedChar);
        }

        return encryptedResult;
    }

    /**
     * Recebe uma lista de BigIntegers e retorna seus valores calculados pela fórmula de desencriptação
     * @param encryptedAsciiNumbers valores da tabela ascii transformados pelo processo de encriptação
     * @return  List<BigInteger> valores calculados com formula de desencriptação
     */
    private List<BigInteger> decryptAsciiNumbers (List<BigInteger> encryptedAsciiNumbers) {
        List<BigInteger> decryptedResult = new ArrayList<>();

        for (BigInteger asciiNumber : encryptedAsciiNumbers) {
            BigInteger decryptedAsciiNumber = asciiNumber.modPow(privateKey, n);
            decryptedResult.add(decryptedAsciiNumber);
        }

        return decryptedResult;
    }

    // Decripta os dados e gera a string a partir da conversao de valores ascii em char

    /**
     * Recebe valores encriptados e gera a String final desencriptada contendo os valores já transformados pela tabela ASCII
     * @param encryptedAsciiNumbers valores calculados pela encriptação da string já em numeros ascii
     * @return  String contendo o resultado da desencriptação
     */
    public String decrypt (List<BigInteger> encryptedAsciiNumbers) {
        List<BigInteger> decryptedAsciiNumbers = decryptAsciiNumbers(encryptedAsciiNumbers);

        // Transforma big integers em int e depois os converte
        // em chars a partir da transformacao da tabela ascii usando casting.
        // Junta todos os chars gerando uma string que será retornada
        String decryptedString = "";
        for (BigInteger asciiNumber : decryptedAsciiNumbers) {
            decryptedString += (char) asciiNumber.intValue();
        }
        return decryptedString;
    }
}