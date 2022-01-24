import os
import sys
import shlex
import hashlib
import zlib
import colorama
import subprocess
import whirlpool
import chilkat2
import pyfiglet
from threading import Thread, Lock
from hashlib import *
from colorama import Fore, Back
from Crypto.Hash import *
 
colorama.init()
def HashFun(hash_, text):
    if hash_ == "md2":
        h = MD2.new()
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "md4":
        h = MD4.new()
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "md5":
        h = MD5.new()
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha1":
        h = hashlib.new("sha1")
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha224":
        h = hashlib.new("sha224")
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha256":
        h = hashlib.new("sha256")
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha384":
        h = hashlib.new("sha384")
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha512/224":
        h = SHA512.new(truncate="224")
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha512/256":
        h = SHA512.new(truncate="256")
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha512":
        h = SHA512.new()
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha3-224":
        h = hashlib.sha3_224()
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha3-256":
        h = hashlib.sha3_256()
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha3-384":
        h = hashlib.sha3_384()
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "sha3-512":
        h = hashlib.sha3_512()
        h.update(b"" + text.encode("utf-8"))
        return h.hexdigest()
    if hash_ == "ripemd128":
        crypt = chilkat2.Crypt2()
        crypt.EncodingMode = "hex"
        crypt.HashAlgorithm = "ripemd128"
        hashStr = crypt.HashStringENC(text)
        return hashStr
    if hash_ == "ripemd160":
        crypt = chilkat2.Crypt2()
        crypt.EncodingMode = "hex"
        crypt.HashAlgorithm = "ripemd160"
        hashStr = crypt.HashStringENC(text)
        return hashStr
    if hash_ == "ripemd256":
        crypt = chilkat2.Crypt2()
        crypt.EncodingMode = "hex"
        crypt.HashAlgorithm = "ripemd256"
        hashStr = crypt.HashStringENC(text)
        return hashStr
    if hash_ == "ripemd320":
        crypt = chilkat2.Crypt2()
        crypt.EncodingMode = "hex"
        crypt.HashAlgorithm = "ripemd320"
        hashStr = crypt.HashStringENC(text)
        return hashStr
    if hash_ == "whirlpool":
        h = whirlpool.new(b"" + text.encode())
        return h.hexdigest()
    if hash_ == "adler32":
        return zlib.adler32(text.encode())
    if hash_ == "crc32":
        return zlib.crc32(text.encode())
    if hash_ == "all":
        md2 = HashFun("md2", text)
        md4 = HashFun("md4", text)
        md5 = HashFun("md5", text)
        sha1 = HashFun("sha1", text)
        sha224 = HashFun("sha224", text)
        sha256 = HashFun("sha256", text)
        sha384 = HashFun("sha384", text)
        sha512_224 = HashFun("sha512/224", text)
        sha512_256 = HashFun("sha512/256", text)
        sha512 = HashFun("sha512", text)
        sha3_224 = HashFun("sha3-224", text)
        sha3_256 = HashFun("sha3-256", text)
        sha3_384 = HashFun("sha3-384", text)
        sha3_512 = HashFun("sha3-512", text)
        ripemd128 = HashFun("ripemd128", text)
        ripemd160 = HashFun("ripemd160", text)
        ripemd256 = HashFun("ripemd256", text)
        ripemd320 = HashFun("ripemd320", text)
        whirlpool1 = HashFun("whirlpool", text)
        adler32 = HashFun("adler32", text)
        crc32 = HashFun("crc32", text)
        return f"""[md2] -> {md2}
[md4] -> {md4}
[md5] -> {md5}
[sha1] -> {sha1}
[sha224] -> {sha224}
[sha256] -> {sha256}
[sha384] -> {sha384}
[sha512/224] -> {sha512_224}
[sha512/256] -> {sha512_256}
[sha512] -> {sha512}
[sha3-224] -> {sha3_224}
[sha3-256] -> {sha3_256}
[sha3-384] -> {sha3_384}
[sha3-512] -> {sha3_512}
[ripemd128] -> {ripemd128}
[ripemd160] -> {ripemd160}
[ripemd256] -> {ripemd256}
[ripemd320] -> {ripemd320}
[whirlpool] -> {whirlpool1}
[adler32] -> {adler32}
[crc32] -> {crc32}"""
class Main:
    def __init__(self):
        self.start_program = True
        while self.start_program == True:
            self.init()
    def init(self):
        try:
            self.command_input = input("\nHash-cap> ")
            if self.command_input.replace(" ", "") != "":
                self.command_input_split = shlex.split(self.command_input)
                try:
                    self.command()
                except IndexError:
                    self.indexeror_()
        except KeyboardInterrupt:
            self.start_program = False
            print("\t")
    def command(self):
        try:
            if (
                str(self.command_input_split[0]).lower() == "help"
                or str(self.command_input_split[0]).lower() == "/?"
                or str(self.command_input_split[0]).lower() == "?"
            ):
                print("\nAll the commands:")
                print(
                    "     • hash                 — A hash function is any function that can be used to map data of arbitrary"
                )
                print(
                    "                              size to fixed-size values. The values returned by a hash function are called hash"
                )
                print(
                    "                              values, hash codes, digests, or simply hashes."
                )
                print(
                    "     • cd                   — Change the shell working directory."
                )
                print("     • cls, clear, clean    — Screen cleaning.")
                print("     • exit, quit, ^C       — Exit from the program.")
                print("     • $cmd                 — Executing a console command.")
                print(
                    "     • help, /?, ?          — Displaying a list of program commands."
                )
                print("\nList of hashes:\t\t\tInformation on wikipedia:")
                print(
                    "\t• --md2\t\t\thttps://en.wikipedia.org/wiki/MD2_(hash_function)."
                )
                print("\t• --md4\t\t\thttps://en.wikipedia.org/wiki/MD4.")
                print("\t• --md5\t\t\thttps://en.wikipedia.org/wiki/MD4.")
                print(
                    "\t• --sha1\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha384\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha512/224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha512/256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha512\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha3-224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha3-256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha3-384\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print(
                    "\t• --sha3-512\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                )
                print("\t• --ripemd128\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                print("\t• --ripemd160\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                print("\t• --ripemd256\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                print("\t• --ripemd320\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                print(
                    "\t• --whirlpool\t\thttps://en.wikipedia.org/wiki/Whirlpool_(hash_function)."
                )
                print("\t• --adler32\t\thttps://en.wikipedia.org/wiki/Adler-32.")
                print(
                    "\t• --crc32\t\thttps://en.wikipedia.org/wiki/Cyclic_redundancy_check."
                )
                print("\nSyntax:")
                print("     <command>                   <parameter>")
                print("     hash                        <hash_type> <parameter>")
                print(
                    "     hash (--comparison or -c)   <hash_type> <parameter_1> <parameter_2>"
                )
                print(
                    "     hash (--brute_force or -bf) <hash_type> <hash> <the_path_to_the_dictionary>"
                )
                print(
                    "\n[*] To display command help, enter only the name of the command."
                )
            if str(self.command_input_split[0]).lower() == "$cmd":
                os.system(self.command_input.replace("$cmd", ""))
            if (
                str(self.command_input_split[0]).lower() == "exit"
                or str(self.command_input_split[0]).lower() == "quit"
                or str(self.command_input_split[0]).lower() == "^c"
            ):
                self.start_program = False
            if (
                str(self.command_input_split[0]).lower() == "cls"
                or str(self.command_input_split[0]).lower() == "clear"
                or str(self.command_input_split[0]).lower() == "clean"
            ):
                try:
                    subprocess.call("cls")
                except:
                    subprocess.call("clear")
            if str(self.command_input_split[0]).lower() == "cd":
                os.chdir(str(self.command_input_split[1]))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--md2"
            ):
                print(HashFun("md2", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--md4"
            ):
                print(HashFun("md4", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--md5"
            ):
                print(HashFun("md5", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha1"
            ):
                print(HashFun("sha1", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha224"
            ):
                print(HashFun("sha224", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha256"
            ):
                print(HashFun("sha256", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha384"
            ):
                print(HashFun("sha384", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha512/224"
            ):
                print(HashFun("sha512/224", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--ha512/256"
            ):
                print(HashFun("ha512/256", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha512"
            ):
                print(HashFun("sha512", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha3-224"
            ):
                print(HashFun("sha3-224", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha3-256"
            ):
                print(HashFun("sha3-256", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha3-384"
            ):
                print(HashFun("sha3-384", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--sha3-512"
            ):
                print(HashFun("sha3-512", str(self.command_input_split[2])))
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--ripemd128"
            ):
                print(HashFun("ripemd128", str(self.command_input_split[2])).lower())
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--ripemd160"
            ):
                print(HashFun("ripemd160", str(self.command_input_split[2])).lower())
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--ripemd256"
            ):
                print(HashFun("ripemd256", str(self.command_input_split[2])).lower())
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--ripemd320"
            ):
                print(HashFun("ripemd320", str(self.command_input_split[2])).lower())
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--whirlpool"
            ):
                print(HashFun("whirlpool", str(self.command_input_split[2])).lower())
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--adler32"
            ):
                print(HashFun("adler32", str(self.command_input_split[2])).lower())
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--crc32"
            ):
                print(HashFun("crc32", str(self.command_input_split[2])).lower())
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--all"
            ):
                print(HashFun("all", str(self.command_input_split[2])).lower())
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--comparison"
                or str(self.command_input_split[1]).lower() == "-c"
            ):
                digest = HashFun(
                    str(self.command_input_split[2].replace("--", "")).lower(),
                    str(self.command_input_split[3]),
                )
                if digest == str(self.command_input_split[4]):
                    print(
                        Fore.GREEN
                        + f"[+] {str(self.command_input_split[3])} == {str(self.command_input_split[4])}"
                        + Fore.WHITE
                    )
                elif digest != str(self.command_input_split[4]):
                    digest = HashFun(
                        str(self.command_input_split[2].replace("--", "")).lower(),
                        str(self.command_input_split[4]),
                    )
                    if digest == str(self.command_input_split[3]):
                        print(
                            Fore.GREEN
                            + f"[+] {str(self.command_input_split[3])} == {str(self.command_input_split[4])}"
                            + Fore.WHITE
                        )
                    else:
                        print(
                            Fore.RED
                            + f"[-] {str(self.command_input_split[3])} != {str(self.command_input_split[4])}"
                            + Fore.WHITE
                        )
            if (
                str(self.command_input_split[0]).lower() == "hash"
                and str(self.command_input_split[1]).lower() == "--brute_force"
                or str(self.command_input_split[1]).lower() == "-bf"
            ):
                if os.path.isfile(str(self.command_input_split[4])) == False:
                    print("[!] Could not find the file.")
                else:
                    try:
                        pass_file = open(str(self.command_input_split[4]), "r")
                    except Exception as error:
                        print(error)
                        print("[!] An error occurred when opening the file.")
                    try:
                        for word in pass_file:
                            digest = HashFun(
                                str(
                                    self.command_input_split[2].replace("--", "")
                                ).lower(),
                                word.encode("utf-8").strip().decode(),
                            )
                            if digest != None:
                                if digest == str(self.command_input_split[3]):
                                    print("\n[+] Bruteforce was successful!")
                                    print(
                                        "[*] Hash type: {}".format(
                                            str(
                                                self.command_input_split[2].replace(
                                                    "--", ""
                                                )
                                            )
                                        )
                                    )
                                    print(
                                        "================[Result found]================\n"
                                    )
                                    print(
                                        str(self.command_input_split[3])
                                        + " -> "
                                        + Fore.GREEN
                                        + word
                                        + Fore.WHITE
                                    )
                                    print(
                                        "=============================================="
                                    )
                                    break
                                else:
                                    print(
                                        "{} != {}".format(
                                            digest, str(self.command_input_split[3])
                                        )
                                    )
                            else:
                                print(
                                    "[!] Error could not find a hash of this type: {}.".format(
                                        str(self.command_input_split[2])
                                    )
                                )
                                break
                    except Exception as error:
                        print(error)
                        print("[!] An error occurred during brute force.")
        except IndexError:
            try:
                if (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--md2"
                ):
                    print("md2 — The MD2 Message Digest Algorithm.")
                    print("Syntax:")
                    print("\thash --md2 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/MD2_(hash_function)."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--md4"
                ):
                    print("md4 — The MD4 Message Digest Algorithm.")
                    print("Syntax:")
                    print("\thash --md4 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/MD4."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--md5"
                ):
                    print("md5 — The MD5 Message Digest Algorithm.")
                    print("Syntax:")
                    print("\thash --md5 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/MD5."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha1"
                ):
                    print("sha1 — SHA-1 (Secure Hash Algorithm 1).")
                    print("Syntax:")
                    print("\thash --sha1 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha224"
                ):
                    print("sha224 — SHA-2 (Secure Hash Algorithm 2).")
                    print("Syntax:")
                    print("\thash --sha224 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha256"
                ):
                    print("sha256 — SHA-2 (Secure Hash Algorithm 2).")
                    print("Syntax:")
                    print("\thash --sha256 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha384"
                ):
                    print("sha384 — SHA-2 (Secure Hash Algorithm 2).")
                    print("Syntax:")
                    print("\thash --sha384 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha512/224"
                ):
                    print("sha512/224 — SHA-2 (Secure Hash Algorithm 2).")
                    print("Syntax:")
                    print("\thash --sha512/224 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha512/256"
                ):
                    print("sha512/256 — SHA-2 (Secure Hash Algorithm 2).")
                    print("Syntax:")
                    print("\thash --sha512/256 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha512"
                ):
                    print("sha512 — SHA-2 (Secure Hash Algorithm 2).")
                    print("Syntax:")
                    print("\thash --sha512 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha3-224"
                ):
                    print("sha3-224 — SHA-3 (Secure Hash Algorithm 3).")
                    print("Syntax:")
                    print("\thash --sha3-224 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha3-256"
                ):
                    print("sha3-256 — SHA-3 (Secure Hash Algorithm 3).")
                    print("Syntax:")
                    print("\thash --sha3-256 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha3-384"
                ):
                    print("sha3-384 — SHA-3 (Secure Hash Algorithm 3).")
                    print("Syntax:")
                    print("\thash --sha3-384 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--sha3-512"
                ):
                    print("sha3-512 — SHA-3 (Secure Hash Algorithm 3).")
                    print("Syntax:")
                    print("\thash --sha3-512 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--ripemd128"
                ):
                    print("ripemd128 — RIPEMD (RIPE Message Digest).")
                    print("Syntax:")
                    print("\thash --ripemd128 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/RIPEMD."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--ripemd160"
                ):
                    print("ripemd160 — RIPEMD (RIPE Message Digest).")
                    print("Syntax:")
                    print("\thash --ripemd160 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/RIPEMD."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--ripemd256"
                ):
                    print("ripemd256 — RIPEMD (RIPE Message Digest).")
                    print("Syntax:")
                    print("\thash --ripemd256 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/RIPEMD."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--ripemd320"
                ):
                    print("ripemd320 — RIPEMD (RIPE Message Digest).")
                    print("Syntax:")
                    print("\thash --ripemd320 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/RIPEMD."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--whirlpool"
                ):
                    print("whirlpool — Whirlpool.")
                    print("Syntax:")
                    print("\thash --whirlpool <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Whirlpool_(hash_function)."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--adler32"
                ):
                    print("adler32 — Adler32.")
                    print("Syntax:")
                    print("\thash --adler32 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Adler-32."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--crc32"
                ):
                    print("crc32 — Crc32.")
                    print("Syntax:")
                    print("\thash --crc32 <parameter>")
                    print(
                        "\n[*] Detailed information about the hash can be viewed on Wikipedia: https://en.wikipedia.org/wiki/Cyclic_redundancy_check."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--all"
                ):
                    print("all — Output all hashes")
                    print("Syntax:")
                    print("\thash --all <parameter>")
                    print("List of hashes:\t\t\tInformation on wikipedia:")
                    print(
                        "\t• --md2\t\t\thttps://en.wikipedia.org/wiki/MD2_(hash_function)."
                    )
                    print("\t• --md4\t\t\thttps://en.wikipedia.org/wiki/MD4.")
                    print("\t• --md5\t\t\thttps://en.wikipedia.org/wiki/MD4.")
                    print(
                        "\t• --sha1\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha384\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha512/224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha512/256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha512\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha3-224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha3-256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha3-384\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha3-512\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print("\t• --ripemd128\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                    print("\t• --ripemd160\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                    print("\t• --ripemd256\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                    print("\t• --ripemd320\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                    print(
                        "\t• --whirlpool\t\thttps://en.wikipedia.org/wiki/Whirlpool_(hash_function)."
                    )
                    print("\t• --adler32\t\thttps://en.wikipedia.org/wiki/Adler-32.")
                    print(
                        "\t• --crc32\t\thttps://en.wikipedia.org/wiki/Cyclic_redundancy_check."
                    )
                elif (
                    str(self.command_input_split[0]).lower() == "hash"
                    and str(self.command_input_split[1]).lower() == "--brute_force"
                    or str(self.command_input_split[1]).lower() == "-bf"
                ):
                    print("--brute_force — Dictionary hash search.")
                    print("Hash Type:")
                    print("\t• --md2")
                    print("\t• --md4")
                    print("\t• --md5")
                    print("\t• --sha1")
                    print("\t• --sha224")
                    print("\t• --sha256")
                    print("\t• --sha384")
                    print("\t• --sha512/224")
                    print("\t• --sha512/256")
                    print("\t• --sha512")
                    print("\t• --sha3-224")
                    print("\t• --sha3-256")
                    print("\t• --sha3-384")
                    print("\t• --sha3-512")
                    print("\t• --ripemd128")
                    print("\t• --ripemd160")
                    print("\t• --ripemd256")
                    print("\t• --ripemd320")
                    print("\t• --whirlpool")
                    print("\t• --adler32")
                    print("\t• --crc32")
                    print("Syntax:")
                    print(
                        "\thash (--brute_force or -bf) <hash_type> <hash> <the_path_to_the_dictionary>"
                    )
                    print("The principle of operation:")
                    print(
                        "\tA brute-force attack is a cryptanalytic attack that can, in theory,"
                    )
                    print("\tbe used to attempt to decrypt any encrypted data")
                    print(
                        "\t(except for data encrypted in an information-theoretically secure manner)."
                    )
            except IndexError:
                if str(self.command_input_split[0]).lower() == "cd":
                    print("cd — Change the shell working directory.")
                    print("Syntax:")
                    print("\tcd <directory>\n")
                    print("Current directory:\t" + os.getcwd())
                if str(self.command_input_split[0]).lower() == "hash":
                    print(
                        "hash —  A hash function is any function that can be used to map data of arbitrary"
                    )
                    print(
                        "\tsize to fixed-size values. The values returned by a hash function are called hash"
                    )
                    print("\tvalues, hash codes, digests, or simply hashes.")
                    print("Syntax:")
                    print("\thash                        <hash_type> <parameter>")
                    print(
                        "\thash (--comparison or -c)   <hash_type> <parameter_1> <parameter_2>"
                    )
                    print(
                        "\thash (--brute_force or -bf) <hash_type> <hash> <the_path_to_the_dictionary>"
                    )
                    print("Hash type:\t\t\tInformation on wikipedia:")
                    print(
                        "\t• --md2\t\t\thttps://en.wikipedia.org/wiki/MD2_(hash_function)."
                    )
                    print("\t• --md4\t\t\thttps://en.wikipedia.org/wiki/MD4.")
                    print("\t• --md5\t\t\thttps://en.wikipedia.org/wiki/MD4.")
                    print(
                        "\t• --sha1\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha384\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha512/224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha512/256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha512\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha3-224\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha3-256\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha3-384\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print(
                        "\t• --sha3-512\t\thttps://en.wikipedia.org/wiki/Secure_Hash_Algorithms."
                    )
                    print("\t• --ripemd128\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                    print("\t• --ripemd160\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                    print("\t• --ripemd256\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                    print("\t• --ripemd320\t\thttps://en.wikipedia.org/wiki/RIPEMD.")
                    print(
                        "\t• --whirlpool\t\thttps://en.wikipedia.org/wiki/Whirlpool_(hash_function)."
                    )
                    print("\t• --adler32\t\thttps://en.wikipedia.org/wiki/Adler-32.")
                    print(
                        "\t• --crc32\t\thttps://en.wikipedia.org/wiki/Cyclic_redundancy_check."
                    )
class Boot:
    def __init__(self):
        print(Fore.RED+pyfiglet.figlet_format("Metros Hash Cap")+Fore.WHITE)
        print("[*] Metros Hash Cap [version 1.0] 2022.")
        print("\n[*] Detailed information on the website: metros-software.ru")
        print(
            "[*] Technical support metros:            metrostechnicalsupp0rt@gmail.com"
        )
        Main()
        print("\n[*] Completing Metros Hash Cap...\n")
if __name__ == "__main__":
    try:
        if sys.argv[1] == "--version" or sys.argv[1] == "-v":
            print("[*] Metros Hash Cap [version 1.0] 2022.")
        if sys.argv[1] == "--clear":
            try:
                subprocess.call("cls")
            except:
                subprocess.call("clear")
            Boot()
    except:
        Boot()