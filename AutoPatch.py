import sys


def distinguish_lang(source: str) -> str:
    #Assume that the language used has already been entered.
    if int(sys.argv[1]) == 0:
        used_lang = "PHP"
    elif int(sys.argv[1]) == 1:
        used_lang = "ASP.NET"
    elif int(sys.argv[1]) == 2:
        used_lang = "Ruby"
    elif int(sys.argv[1]) == 3:
        used_lang = "Java"
    elif int(sys.argv[1]) == 4:
        used_lang = "Scala"
    elif int(sys.argv[1]) == 5:
        used_lang = "Python"
    elif int(sys.argv[1]) == 6:
        used_lang = "JavaScript"
    elif int(sys.argv[1]) == 7:
        used_lang = "perl"
    else:
        print("Error: Undefined language type")
        sys.exit()
    return used_lang


def get_vuln_type() -> str:
    if int(sys.argv[2]) == 0:
        vuln_name = "SQL_Injection"
    elif int(sys.argv[2]) == 1:
        vuln_name = "XSS"
    elif int(sys.argv[2]) == 2:
        vuln_name = "File Inclusion"
    elif int(sys.argv[2]) == 3:
        vuln_name = "Command Injection"
    else:
        print("Error: Undefined vulnerability type")
        sys.exit()
    return vuln_name


def find_insert_index(code: str, frame: str) -> int:
    index = 0

    return index


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python AutoPatch.py [Language] [vulnerability type]")
        sys.exit()

    with open("code.txt", "r") as f:
        data = f.read()

    lang = distinguish_lang(data)
    vuln_type = get_vuln_type()
    location_index = find_insert_index(data, lang)

    with open("./vulnList/" + vuln_type + "-" + lang + ".txt", "r") as f:
        patch_code = f.read()

    result = data[:location_index] + patch_code + data[location_index:]
    print(result)
