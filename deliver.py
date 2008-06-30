#!/usr/bin/python2.5

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_SERIALIZABLE
import smtplib
import os
import sys

database = "spamassassin"
user = "qmail"
password = "38hb75"

def main():
    method = os.getenv("REQUEST_METHOD")
    if method == "GET":
        _confirm("http://" + os.getenv("SERVER_NAME") +
                 os.getenv("SCRIPT_NAME") + os.getenv("PATH_INFO"))
    elif method != "POST":
        sys.exit()
        
    pathInfo = os.getenv("PATH_INFO")
    if pathInfo[0] != "/":
        _invalidId()
        
    deliveryId = pathInfo[1:]
    connection = psycopg2.connect(database=database, user=user,
                                  password=password)

    connection.set_isolation_level(ISOLATION_LEVEL_SERIALIZABLE)
    cursor = connection.cursor()
    try:
        cursor.execute(
            """SELECT recipient, spam_id FROM spam_recipients
            WHERE delivery_id = %s""",
            [deliveryId])
        if cursor.rowcount == 0:
            _invalidId()
            
        recipient, savedMailId = cursor.fetchone()

        # Determine the real recipient.
        cursor.execute(
            "SELECT delivery FROM quarantine_recipients WHERE %s ~ regexp",
            [recipient])
        if cursor.rowcount != 0:
            recipient = cursor.fetchone()[0]

        cursor.execute(
             "SELECT mail_from, contents FROM spam WHERE id = %s",
             [savedMailId])
        mailFrom, msg = cursor.fetchone()
        
        # Deliver the message.
        mailServer = smtplib.SMTP("localhost")
        mailServer.sendmail(mailFrom, recipient, msg, ["BODY=8BITMIME"])
        mailServer.quit()

        cursor.execute(
            "DELETE FROM spam_recipients WHERE delivery_id = %s",
            [deliveryId])
        cursor.execute(
            """SELECT COUNT(*) FROM spam_recipients WHERE spam_id = %s""",
            [savedMailId])
        number = cursor.fetchone()[0]
        if number == 0:
            cursor.execute("DELETE FROM spam WHERE id = %s", [savedMailId])
        
        connection.commit()
        _success()
    except:
        connection.rollback()
        raise
    
def _invalidId():
    print "Content-Type: text/html"
    print
    print "<html><head><title>Invalid Message ID</title></head>"
    print "<body><h2>An invalid message id was specified.</h2></body></html>"
    sys.exit()
    
def _success():
    print "Content-Type: text/html"
    print
    print "<html><head><title>Message Queued For Delivery</title></head>"
    print "<body>"
    print "<h2>Your message has been queued for delivery to your mailbox.</h2>"
    print "</body></html>"
    sys.exit()
    
def _confirm(url):
    print "Content-Type: text/html"
    print
    print "<html><head><title>Confirm Message Delivery</title></head>"
    print "<body>"
    print "<h2>Click the button to deliver the message to your mailbox.</h2>"
    print "<form method='POST' enctype='application/x-www-form-urlencoded'"
    print "action='%s'" % url, ">"
    print "<input type='submit' value='Deliver message'></form></body></html>"
    sys.exit()

if __name__ == "__main__":
    main()
