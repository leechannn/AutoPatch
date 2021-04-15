import sys

class Patch:
    def __init__(self):
        self.func = ''
        self.reg = ''

    def set_func(self, func):
        self.func = func

    def set_reg(self, reg):
        self.reg = reg.strip()


def distinguish_lang() -> str:
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
        used_lang = "Perl"
    else:
        print("Error: Undefined language type")
        sys.exit()
    return used_lang


def get_vuln_type() -> str:
    if int(sys.argv[2]) == 0:
        vuln_name = "SQL Injection"
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


def get_patch_info(lang, vuln_type):
    with open('./vulnList/' + vuln_type + "-" + lang + ".txt", 'r') as f:
        lines = f.readlines()

    text_type = ''
    vuln = Patch()
    tmp_str = ''

    for line in lines:
        if line[:10] == '%%%%%%%%%%' and text_type == '':
            text_type = line[10:14]
        elif line[:10] == '%%%%%%%%%%' and text_type == 'FUNC':
            vuln.set_func(tmp_str)
            text_type = ''
            tmp_str = ''
        elif line[:10] == '%%%%%%%%%%' and text_type == 'DECR':
            vuln.set_reg(tmp_str)
            text_type = ''
            tmp_str = ''
        else:
            tmp_str = tmp_str + line

    print(vuln.func)
    print(vuln.reg)
    return vuln


def find_insert_index(code: str, frame: str) -> int:
    index = 0

    return index


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python AutoPatch.py [Language] [vulnerability type]")
        sys.exit()

    with open("code.txt", "r") as f:
        data = f.read()

    lang = distinguish_lang()
    vuln_type = get_vuln_type()
    vuln_patch_info = get_patch_info(lang, vuln_type)
    '''location_index = find_insert_index(data, lang)

    with open("./vulnList/" + vuln_type + "-" + lang + ".txt", "r") as f:
        patch_code = f.read()

    result = data[:location_index] + patch_code + data[location_index:]
    print(result)'''
