import os
import subprocess
import re
import time

# Patrones de vulnerabilidad para diferentes lenguajes
patterns = {
    "PHP": {
        "XSS": [r"/\becho\b.*\$_GET\b/", r"/echo\s+\$_REQUEST/"],
        "SQL Injection": [r"(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\s+\w+\s+(?:WHERE|VALUES|SET)"],
        "OS Command Injection": [r"(?:exec|system|shell_exec|passthru)\s*\("],
        "Insecure Deserialization": [r"(?:unserialize)\s*\("]
    },
    "Python": {
        "XSS": [r"/\bprint\b.*\brequest\.GET\b/", r"/print\s+request\.GET/"],
        "SQL Injection": [r"(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\s+\w+\s+(?:WHERE|VALUES|SET)"],
        "OS Command Injection": [r"(?:os\.system|subprocess\.call|subprocess\.Popen)\s*\("]
    },
    "C++": {
        "XSS": [r"/\bcout\b.*\bcin\b/", r"/cout\s+cin/"],
        "SQL Injection": [r"(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\s+\w+\s+(?:WHERE|VALUES|SET)"]
    },
    "JavaScript": {
        "XSS": [r"/\bconsole\.log\b.*\breq\.query\b/", r"/console\.log\s+req\.query/"],
        "SQL Injection": [r"(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\s+\w+\s+(?:WHERE|VALUES|SET)"]
    },
    "Java": {
        "XSS": [r"/model\.addAttribute.*\brequest\.getParameter\b/", r"/model\.addAttribute\s+request\.getParameter/"],
        "SQL Injection": [r"(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\s+\w+\s+(?:WHERE|VALUES|SET)"]
    },
    "C#": {
        "XSS": [r"/\bConsole\.WriteLine\b.*\bRequest\.QueryString\b/", r"/Console\.WriteLine\s+Request\.QueryString/"],
        "SQL Injection": [r"(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\s+\w+\s+(?:WHERE|VALUES|SET)"]
    },
    "Ruby": {
        "XSS": [r"/\blog\b.*\bparams\b/", r"/puts\s+params/"],
        "SQL Injection": [r"(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\s+\w+\s+(?:WHERE|VALUES|SET)"]
    }
}

def search_vulnerabilities(language):
    try:
        if language not in patterns:
            raise Exception(f"No hay patrones de vulnerabilidad disponibles para {language}")

        print(f"\nBuscando vulnerabilidades en archivos {language} (Lenguaje: {language.capitalize()})")
        for category, category_patterns in patterns[language].items():
            for pattern in category_patterns:
                # Usando comandos find y grep para búsqueda eficiente
                grep_cmd = f"find . -type f -name '*.{language.lower()}' -exec grep -Hn -E '{pattern}' {{}} +"
                result = subprocess.run(grep_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.stdout:
                    # Destacando la ubicación en un color llamativo
                    print(f"\n\033[95mPatrón de vulnerabilidad encontrado en {category}:\033[0m {pattern}")
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            location, code = line.split(':', 1)
                            print(f"\033[93m{location}:\033[0m{code}")

        print("\nBúsqueda completada.")
    except Exception as e:
        print(e)

def main():
    print("Detectando lenguaje de programación...")
    time.sleep(1)
    # Realizar búsqueda automática
    for language in patterns.keys():
        search_vulnerabilities(language)

if __name__ == "__main__":
    main()
