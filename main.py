from random import randrange
import sys
import math
import binascii
import hashlib
import os


def countBits(number):
    return int((math.log(number) / math.log(2)) + 1)


# IMPORTANT: The block size MUST be less than or equal to the key size!
DEFAULT_BLOCK_SIZE = 128
BYTE_SIZE = 256


def get_u_r(num):
    u = 0
    num -= 1

    while True:
        u += 1
        num //= 2
        if u != 0 and num % 2 != 0:
            break
    return (u, num)


def modular_pow(base, exponent, modulus):
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 0:
        if (exponent % 2 == 1):
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result


def miller_rabin(p, s):
    if p == 2:
        return True
    if p % 2 == 0:
        return False

    u, r = get_u_r(p)
    for i in range(s):
        a = randrange(2, p - 1)
        z = modular_pow(a, r, p)

        if z != 1 and z != (p - 1):
            for j in range(u):
                z = modular_pow(z, 2, p)
                if z == p - 1:
                    break
            else:
                return False
    return True


def get_rand_prime(nbits):
    while True:
        p = randrange(2 ** (nbits - 1), 2 ** nbits - 1)
        # print(p)
        if miller_rabin(p, 50):
            return p


def inverse(ra, rb):
    if rb > ra:
        ra, rb = rb, ra

    modulos = ra
    mult = [(1, 0), (0, 1)]
    while True:
        # print(str(ra) + " = " + str(rb) + "*", end='')
        mod = ra % rb
        q = (ra - mod) // rb
        # print(str(q)+" + " + str(mod))
        ra = rb
        rb = mod
        mult = [
            (mult[1][0], mult[1][1]),
            ((-q * mult[1][0]) + mult[0][0], (-q * mult[1][1]) + mult[0][1])
        ]
        if mod == 0:
            # print("GCD = " + str(ra))
            if ra == 1:
                return mult[0][1] % modulos
            else:
                return -1


def CRT(y, d, p, q):
    n = p * q

    # 1- Convert to CRT domain
    yp = y % p
    yq = y % q
    # print("(yp, yq) = ", str((yp, yq)))

    # 2- Do the computations
    dp = d % (p - 1)
    dq = d % (q - 1)
    # print("(dp, dq) = ", str((dp, dq)))

    xp = pow(yp, dp, p)
    xq = pow(yq, dq, q)
    # print("(xp, xq) = ", str((xp, xq)))

    # 3- Combine
    cp = pow(q, p - 2, p)
    cq = pow(p, q - 2, q)
    # print(cq == pow(p, q-2, q))
    # print("(cp, cq) = ", str((p, q)))

    x = ((q * cp * xp) + (p * cq * xq)) % n
    # print("x = ", x, "mod " + str(n))
    return x


def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts a string message to a list of block integers. Each integer
    # represents 128 (or whatever blockSize is set to) string characters.

    messageBytes = message.encode('ascii')  # convert the string to bytes

    blockInts = []
    for blockStart in range(0, len(messageBytes), blockSize):
        # Calculate the block integer for this block of text
        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
            blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts


def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts a list of block integers to the original message string.
    # The original message length is needed to properly convert the last
    # block integer.
    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                # Decode the message string for the 128 (or whatever
                # blockSize is set to) characters from this block integer.
                asciiNumber = blockInt // (BYTE_SIZE ** i)
                blockInt = blockInt % (BYTE_SIZE ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)


def keyGen(nbits):
    p = get_rand_prime(nbits)
    print("prime_p : \n", p)
    q = get_rand_prime(nbits)
    while p == q or countBits(p * q) < (nbits * 2):
        q = get_rand_prime(nbits)
    print("prime_q : \n", q)
    n = p * q
    print("n : \n", n)
    phi = (p - 1) * (q - 1)
    print("phi : \n", phi)
    e = randrange(2 ** 16, 2 ** 17)
    d = inverse(phi, e)
    while d == -1:
        e = randrange(2 ** 16, 2 ** 17)
        d = inverse(phi, e)

    print("e : \n", e)
    print("d : \n", d)

    # write the public keys n and e to a file
    pb = input('Public key file name:')
    pr = input('Private key file name:')
    f_public = open(pb + '.txt', 'w')
    f_public.write(str(countBits(n)) + '\n')
    f_public.write(str(n) + '\n')
    f_public.write(str(e) + '\n')
    f_public.close()

    # write the private keys n, d, e to a file
    f_private = open(pr + '.txt', 'w')
    f_private.write(str(countBits(n)) + '\n')
    f_private.write(str(n) + '\n')
    f_private.write(str(d) + '\n')
    f_private.write(str(p) + '\n')
    f_private.write(str(q) + '\n')
    f_private.close()


def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Converts the message string into a list of block integers, and then
    # encrypts each block integer.
    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(message, blockSize):
        # ciphertext = plaintext ^ e mod n
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):
    decryptedBlocks = []
    d, p, q = key
    for block in encryptedBlocks:
        # plaintext = ciphertext ^ d mod n
        decryptedBlocks.append(CRT(block, d, p, q))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)


def readPBKeyFile(keyFilename):
    fo = open(keyFilename)
    keySize = int(fo.readline())
    n = int(fo.readline())
    e = int(fo.readline())
    fo.close()
    return (keySize, n, e)


def readPVKeyFile(keyFilename):
    fo = open(keyFilename)
    keySize = int(fo.readline())
    n = int(fo.readline())
    d = int(fo.readline())
    p = int(fo.readline())
    q = int(fo.readline())
    fo.close()
    return (keySize, n, d, p, q)


def encryptAndWriteToFile(messageFilename, keyFilename, message, blockSize=DEFAULT_BLOCK_SIZE):
    keySize, n, e = readPBKeyFile(keyFilename)

    # Check that key size is greater than block size.
    if keySize < blockSize * 8:  # * 8 to convert bytes to bits
        sys.exit(
            'ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Either decrease the block size or use different keys.' % (
                blockSize * 8, keySize))

    # Encrypt the message
    encryptedBlocks = encryptMessage(message, (n, e), blockSize)

    # Convert the large int values to one string value.
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = '\n---endBlock---\n'.join(encryptedBlocks)

    # Write out the encrypted string to the output file.
    encryptedContent = '%s_%s_%s' % (len(message), blockSize, encryptedContent)
    fo = open(messageFilename, 'wb')
    fo.write(encryptedContent.encode('utf-8'))
    fo.close()
    # Also return the encrypted string.
    return encryptedContent


def readFromFileAndDecrypt(messageFilename, keyFilename):
    keySize, n, d, p, q = readPVKeyFile(keyFilename)
    # Read in the message length and the encrypted message from the file.
    fo = open(messageFilename)
    content = fo.read()
    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)

    # Check that key size is greater than block size.
    if keySize < blockSize * 8:  # * 8 to convert bytes to bits
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be '
                 'equal to or greater than the key size.' % (blockSize * 8, keySize))

    # Convert the encrypted message into large int values.
    encryptedBlocks = []
    for block in encryptedMessage.split('\n---endBlock---\n'):
        encryptedBlocks.append(int(block))

    # Decrypt the large int values.
    return decryptMessage(encryptedBlocks, messageLength, (d, p, q), blockSize)


# Digital signing
def sign(keyFilename, message):
    keySize, n, d, p, q = readPVKeyFile(keyFilename)
    hashed = hashlib.sha1(message.encode()).hexdigest()
    print("Signature: ", pow(int(hashed, 16), d, n))
    return pow(int(hashed, 16), d, n)


# Verify the Digital signature
def verify(keyFilename, message, signed_message):
    keySize, n, e = readPBKeyFile(keyFilename)
    hashed = hashlib.sha1(message.encode()).hexdigest()
    if pow(signed_message, e, n) == int(hashed, 16):
        print("Verify OK")
        return True
    print("Verify Failed")
    return False


def str_imple():
    # Implement on a string
    # message = '"You can fool all of the people some of the time, and some of the people all of the time, but you can not fool all of the people all of the time." - Abraham Lincoln'
    instruction = input('Would you like to encrypt or decrypt? (Enter e or d): ')
    if instruction == 'e':
        message = input('Type message to encrypt:\n')
        pubKeyFilename = input('Public key file name to encrypt:')
        filename = input('Type ciphertext file name:')
        print('Encrypting and writing to %s...' % (filename + '.bin'))
        encryptedText = encryptAndWriteToFile(filename + '.bin', pubKeyFilename + '.txt', message)
        print('Encrypted text:')
        print(encryptedText)

        # create digital signature
        key_c = input('Do you want to generate new public and private keys? (y or n) ')
        if (key_c == 'y'):
            l = input('Type key length for digital signing:')
            keyGen(int(l))
        privKeyFilename = input('Private key file name of the Signature:')
        signature = sign(privKeyFilename + '.txt', message)
        fname = input('Type signature file name:')
        with open(fname + '.bin', "wb") as binary_file:
            binary_file.write(str(signature).encode('utf-8'))
        print("Encrypt success, send both ciphertext and signature file")

    elif (instruction == 'd'):
        filename = input('Type ciphertext file name:')
        privKeyFilename = input('Private key file name to decrypt:')
        print('Decryption...')
        print('Reading from %s and decrypting...' % (filename + '.bin'))
        decryptedText = readFromFileAndDecrypt(filename + '.bin', privKeyFilename + '.txt')
        print('Decrypted text:')
        print(decryptedText)

        # verify digital signature
        pubKeyFilename = input('Public key file name of the Signature:')
        fname = input('Type signature file name:')
        with open(fname + '.bin', "rb") as binary_file:
            data = binary_file.read()
        verify(pubKeyFilename + '.txt', decryptedText, int(data))
    else:
        print('Unknown command.')


def file_imple():
    instruction = input('Would you like to encrypt or decrypt? (Enter e or d): ')
    if instruction == 'e':
        fname = input('File name:')
        pubKeyFilename = input('Public key file name to encrypt:')
        filename = input('Type ciphertext file name:')
        with open(fname, "rb") as binary_file:
            data = binary_file.read()
        message = binascii.hexlify(data).decode('utf-8')  # convert hex data to strings
        print('Encrypting and writing to %s...' % (filename + '.bin'))
        encryptedText = encryptAndWriteToFile(filename + '.bin', pubKeyFilename + '.txt', message)
        print('Encrypted text:')
        print(encryptedText)

        # create digital signature
        key_c = input('Do you want to generate new public and private keys? (y or n) ')
        if (key_c == 'y'):
            l = input('Type key length for digital signing:')
            keyGen(int(l))
        privKeyFilename = input('Private key file name of the Signature:')
        signature = sign(privKeyFilename + '.txt', message)
        fname = input('Type signature file name:')
        with open(fname + '.bin', "wb") as binary_file:
            binary_file.write(str(signature).encode('utf-8'))
        print("Encrypt success, send both ciphertext and signature file")

    elif (instruction == 'd'):
        filename = input('Type ciphertext file name:')
        privKeyFilename = input('Private key file name to decrypt:')
        print('Decryption...')
        print('Reading from %s and decrypting...' % (filename + '.bin'))
        decryptedText = readFromFileAndDecrypt(filename + '.bin', privKeyFilename + '.txt')
        fname = input('File name:')
        with open(fname, "wb") as binary_file:
            # Write to file
            binary_file.write(binascii.unhexlify(decryptedText))
        print('Decrypted into a clone file')

        # verify digital signature
        pubKeyFilename = input('Public key file name of the Signature:')
        fname = input('Type signature file name:')
        with open(fname + '.bin', "rb") as binary_file:
            data = binary_file.read()
        verify(pubKeyFilename + '.txt', decryptedText, int(data))
    else:
        print('Unknown command.')


def main():
    # Generate key
    key_c = input('Do you want to generate new public and private keys? (y or n) ')
    if (key_c == 'y'):
        len = input('Type key length (greater than 512):')
        keyGen(int(len))

    instruction = input('Would you like to work on a string or a file? (Enter s or f): ')
    if instruction == 's':
        str_imple()
    elif instruction == 'f':
        file_imple()
    else:
        print('Unknown command.')


main()
os.system('pause')
