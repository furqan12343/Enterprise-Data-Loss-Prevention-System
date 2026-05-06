import hashlib
import sqlite3
from simhash import Simhash

# Define the central database where sensitive hashes are stored
DATABASE = 'database.db'

def hash_data(data_bytes):
    return hashlib.sha3_256(data_bytes).hexdigest()

def get_fuzzy_hash(data_bytes):
    try:
        text = data_bytes.decode('utf-8', errors='ignore')
    except:
        text = str(data_bytes)
    return str(Simhash(text).value)

def check_hash_in_db(hash_value):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Query the database to see if this hash is already registered
    cursor.execute('SELECT id FROM sensitive_hashes WHERE hash_value = ?', (hash_value,))
    match = cursor.fetchone()
    
    conn.close()
    
    # If match is not None, we found it in the database!
    return match is not None

def check_fuzzy_hash_in_db(incoming_fuzzy_hash):
    """
    Checks if incoming fuzzy hash matches any stored fuzzy hash with 70% or higher similarity.
    SimHash uses a 64-bit integer. 70% similarity means maximum 19 differing bits (Hamming Distance).
    """
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT fuzzy_hash_value FROM sensitive_hashes')
    rows = cursor.fetchall()
    conn.close()
    
    inc_int = int(incoming_fuzzy_hash)
    for row in rows:
        stored_int = int(row[0])
        # Calculate Hamming distance (number of bit differences)
        distance = bin(inc_int ^ stored_int).count('1')
        # 64 bits * 30% difference = 19.2 bits maximum difference
        if distance <= 19:
            return True
    return False
