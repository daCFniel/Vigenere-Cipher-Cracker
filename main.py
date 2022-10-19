import string

# Vigenere Cipher code cracker

alphabet = string.ascii_uppercase  # Get the english alphabet consisting of 26 letters "abcdefghijklmnopqrstuvwxyz"
letter_count = dict.fromkeys(alphabet, 0)  # Dictionary for storing number of occurances of the letters
similarity_scores = dict.fromkeys(list(range(26)), 0)  # Dictionary for storing similarity scores
frequency_table = {  # Relative frequency of letters in the English language (taken from Wikipedia)
    'A': 8.2,
    'B': 1.5,
    'C': 2.8,
    'D': 4.3,
    'E': 13.0,
    'F': 2.2,
    'G': 2.0,
    'H': 6.1,
    'I': 7.0,
    'J': 0.15,
    'K': 0.77,
    'L': 4.0,
    'M': 2.4,
    'N': 6.7,
    'O': 7.5,
    'P': 1.9,
    'Q': 0.095,
    'R': 6.0,
    'S': 6.3,
    'T': 9.1,
    'U': 2.8,
    'V': 0.98,
    'W': 2.4,
    'X': 0.15,
    'Y': 2.0,
    'Z': 0.074
}


def vigenere_generate_key(message, key):
    if len(message) == len(key):
        return key
    else:
        for i in range(len(message) - len(key)):
            key += key[i % len(key)]
    return key


def vigenere_decrypt(encrypted_message, key):
    decrypted_message = ""
    for i in range(len(encrypted_message)):
        x = (ord(encrypted_message[i]) - ord(key[i]) + 26) % 26
        x += ord('A')  # convert into alphabet (ASCII)
        decrypted_message += chr(x)
    return decrypted_message


# analyze and crack the ciphertext
# for which the key length is known (6 letter key in this case)
# return keyword that was user to encrypt the text
def vigenere_analyze(encrypted_message):
    full_keyword = ""  # keyword to be cracked
    groups = {  # for storing 6 parts of the ciphertext
        0: "",
        1: "",
        2: "",
        3: "",
        4: "",
        5: ""
    }
    # split up ciphertext into 6 groups
    for i in range(len(encrypted_message)):
        groups[i % 6] += encrypted_message[i]
    for n in groups:  # do frequency analysis for each group
        for letter in alphabet:  # decrypt the group with each letter
            plain_text = ""
            temp_key = vigenere_generate_key(groups[n], letter)

            for i in range(len(groups[n])):
                x = (ord(groups[n][i]) - ord(temp_key[i]) + 26) % 26
                x += ord('A')  # convert into alphabet (ASCII)
                plain_text += chr(x)

            # frequency analysis

            # count the letters in the message
            for l in alphabet:
                letter_count[l] = plain_text.count(l)
            # calculate similarity score
            similarity_score = 0
            for l in letter_count:
                similarity_score += letter_count[l] * frequency_table[l]

            similarity_scores[ord(letter) - ord('A')] = similarity_score

        group_key = highest_score(similarity_scores)  # pick the candidate key for this group (one letter A-Z)

        full_keyword += chr(group_key + ord('A'))  # add the candidate key to the full keyword

    return full_keyword


def highest_score(d):
    v = list(d.values())
    k = list(d.keys())
    return k[v.index(max(v))]


# main
if __name__ == "__main__":
    encrypted_message = "RLTXNYRIIBMINYWAFOJRJERRHWYWZOSVZMCXNYLPQSMGJBFOCIXXCBZXNWLYEX" \
                        "MMLSFLYPCBZGYQTSSMJAFKCHWWNZDHYWXOQSFVBDGIWMUKRRTNSBSLJZPKRLSM" \
                        "QCSSGMDOZVJLRORWYZGOCXTJSCXLJZQOKJFOYSMSAMPDGIGZCKJJFARDZFQMUS" \
                        "SLRWPONVQMQCRYHKCCRESLRRDCXIRNNASJMDGSSBFORERMQSCIXWRRZXYPCSQK" \
                        "QILMDWIQBXNXRMCDSLJZCGZWFBDSQWYAMWDXMQLQZAPEYBCMSPCKQMSOCKBLTB" \
                        "FOQIFBYXCHWQLUAYYBFSRGTCJNMSYJCORGFXCNLSWMMFDVYPCKLSZVRYEIFBGX" \
                        "FHTVCGZWXUYVKSSJMDGWNLCCAVJIIPZWYWTOQLJZMCDESLROKPNVERDVYPCRNY" \
                        "WIRGGMHPFOLMLPRLDICXCMSIIBMNHRSMPGDRYWDPSSYPCWHPQMPCHRFUCMGESQ" \
                        "AKKTZZQEZRHMMPSLJXJKMSKARECCNVEDGEYJSCHRJAQGGMHPFKCFJMLRHWTVJI" \
                        "OVFKRSBEQZCKRSSNMBBSRQLQGIWMURDRMMUKRKTVCDDWXARYNHFBRRDANVBYVE" \
                        "SLNBDWJVRVXWFEFSRJTZKMQSXAGXFXMMEBDEYARYMIGZGNFIBPGMGGTVBEBXJL" \
                        "RYSLJUGVKTWMKSRIXPCCZRPJCRHRIQRMQSXACNSLJZYSKAFGZOXSSLYXCHNAYZ" \
                        "OIFZCNSLJVUSSLTCRKRMLPQRDXZZLOCLJZYDSISBGYMXTBFOQSTUYXCFJOYXBP" \
                        "JIPSMKYPCDZFQMYXCWJBRSMKNBGXNVIMPD"
    keyword = vigenere_analyze(encrypted_message)
    print("\nThe keyword is:", keyword)
    key = vigenere_generate_key(encrypted_message, keyword)
    decrypted_message = vigenere_decrypt(encrypted_message, key)
    print("Decrypted message is:")
    print(decrypted_message)
