import mysql.connector

def connect_to_database():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="your_username",
            password="your_password",
            database="idps_db",
            port=3307
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

def store_alert(message, details):
    conn = connect_to_database()
    if conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO alerts (message, details) VALUES (%s, %s)", (message, details))
        conn.commit()
        cursor.close()
        conn.close()

def get_malicious_patterns():
    conn = connect_to_database()
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM malicious_patterns")
        patterns = cursor.fetchall()
        cursor.close()
        conn.close()
        return patterns
    return []

def store_scan_result(filename, result):
    conn = connect_to_database()
    if conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scanned_files (filename, result) VALUES (%s, %s)", (filename, result))
        conn.commit()
        cursor.close()
        conn.close()