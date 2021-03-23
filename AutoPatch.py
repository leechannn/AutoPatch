def distinguish_lang(source: str) -> str:
    frame = "PHP"
    return frame

def get_vuln_type():
    vuln_type = "SQL_Injection"
    return vuln_type


if __name__ == '__main__':
    with open("code.txt", "r") as f:
        data = f.read()

    lang = distinguish_lang(data)
    vuln_type = get_vuln_type()

    with open("./vulnList/" + vuln_type + "-" + lang + ".txt", "r") as f:
        patch_code = f.read()




