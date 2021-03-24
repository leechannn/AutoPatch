import sys


def distinguish_lang(source: str) -> str:
    frame = "PHP"
    return frame


def get_vuln_type() -> str:
    vuln_name = "SQL_Injection"
    return vuln_name


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python AutoPatch.py [index]")
        sys.exit()

    location_index = int(sys.argv[1])

    with open("code.txt", "r") as f:
        data = f.read()

    lang = distinguish_lang(data)
    vuln_type = get_vuln_type()

    with open("./vulnList/" + vuln_type + "-" + lang + ".txt", "r") as f:
        patch_code = f.read()

    result = data[:location_index] + patch_code + data[location_index:]
    print(result)
