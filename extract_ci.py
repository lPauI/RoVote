import cv2
import pytesseract
import re
import tempfile
import os

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

def find_cnp_from_ci(ci_path):
    image = cv2.imread(ci_path)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    gray, img_bin = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
    gray = cv2.bitwise_not(img_bin)

    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
    temp_filename = temp.name
    temp.close()
    
    cv2.imwrite(temp_filename, gray)
    
    extracted_text = pytesseract.image_to_string(temp_filename)
    
    os.unlink(temp_filename)

    possible_matches = re.search(r'\d{13}', extracted_text)
    if not possible_matches:
        return 'CNP was not found'
        
    matches = re.search(r'^[1-6]\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?:(?!999)\d{3}|999)\d{3}$', possible_matches.group(0))

    if not matches:
        return 'CNP was not found'

    return matches.group(0)
