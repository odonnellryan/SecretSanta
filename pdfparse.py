from collections import Counter

import PyPDF2
import re
import csv
import os

dir_1 = "C:\\Users\\odonn\\Downloads\\2020 statements"
dir_2 = "C:\\Users\\odonn\\Downloads\\2021 statements"


def extract_statement_info(pdf_path):
    # Open the PDF file
    with open(pdf_path, 'rb') as pdf_file:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        pattern = re.compile(r'^\d{2}/\d{2}')

        for page in pdf_reader.pages:

            text = page.extract_text()
            lines = text.split('\n')

            for line in lines:
                line = line.replace(",", "")
                if "daily ending balance" in line.lower():
                    return
                if pattern.match(line):

                    desc = line
                    m_p = r'\d+\.\d+$'

                    matches = re.findall(m_p, line)

                    if matches:
                        yield f"{desc} +  {float(matches[0]) * -1}"
                        desc = ""
                    else:
                        desc += line


def write_to_csv(csv_name, directory_path):
    with open(csv_name, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Date", "Item", "Value"])
        for filename in os.listdir(directory_path):
            pa = os.path.join(directory_path, filename)
            if os.path.isfile(pa):
                for line in extract_statement_info(pa):
                    cols = line.split(" ")
                    csv_writer.writerow([cols[0], " ".join(cols[1:-1]), cols[-1]])


def get_tokens(directories):
    tokens = []
    for directory_path in directories:
        for filename in os.listdir(directory_path):
            pa = os.path.join(directory_path, filename)
            if os.path.isfile(pa):
                if not 'pdf' in filename.lower():
                    continue
                for line in extract_statement_info(pa):
                    word_groups = re.findall(r'[^\W\d_]+(?:\s+[^\W\d_]+)*', line)
                    tokens.extend(word_groups)
    return tokens


tokens = get_tokens([dir_1, dir_2])

word_count = Counter(tokens)

most_common_words = word_count.most_common(100)

for word, count in most_common_words:
    if len(word) < 4:
        continue
    print(word)

# write_to_csv("2020.csv", dir_1)
# write_to_csv("2021.csv", dir_2)
