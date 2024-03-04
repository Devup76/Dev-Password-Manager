import dearpygui.dearpygui as dpg
from argon2 import PasswordHasher
import sqlite3
import os
from datetime import date

today = date.today()

def verifyCreatedMasterPassword():
    if os.path.isfile("devPasswordManager.db"):
        #print("User account already created!")
        dpg.set_primary_window(login_window, True)
        dpg.configure_item(login_window, show=True)
        return True
    else:
        dpg.set_primary_window(cua_window, True)
        dpg.configure_item(cua_window, show=True)

# Create context for dpg usage #
dpg.create_context()
dpg.create_viewport(title="Dev's Pasword Manager", width=800, height=400)

# Call the createUserAccount(cua) window #
def createUserAccount():
    dpg.configure_item(cua_window, show=True)
    dpg.set_primary_window(cua_window, True)
    dpg.configure_item(login_window, show=False)

# Call the loginWindow window from cua #
def loginWindow():
    dpg.configure_item(login_window, show=True)
    dpg.set_primary_window(login_window, True)
    dpg.configure_item(cua_window, show=False)

# Call the main window from CUA #
def main_window_From_CUA():
    dpg.configure_item(main_window, show=True)
    dpg.set_primary_window(main_window, True)
    dpg.configure_item(cua_window, show=False)

def main_window_from_loginWindow():
    dpg.configure_item(main_window, show=True)
    dpg.set_primary_window(main_window, True)
    dpg.configure_item(login_window, show=False)

# Use argon2 to encrypt the password #
def hash_and_encrypt(password):
    ph = PasswordHasher()
    hash = ph.hash(password)
    hash
    ph.verify(hash, password)
    ph.check_needs_rehash(hash)
    print(hash)
    return hash

# Hash the master password and create the local db and insert the master password into it. #
def hash_and_create_db(password, date):
    ph = PasswordHasher()
    hash = ph.hash(password)
    hash
    ph.verify(hash, password)
    ph.check_needs_rehash(hash)
    print(hash)

    con = sqlite3.connect("devPasswordManager.db")
    cur = con.cursor()
    cur.execute("CREATE TABLE userPasswords(type, application, creationDate, hash)")
    cur.execute("INSERT INTO userPasswords(type, application, creationDate, hash) VALUES (?, ?, ?, ?)", ("master", "devPasswordManager", date, hash))
    con.commit()
    res = cur.execute("SELECT * FROM userPasswords")
    print(res.fetchall())


# Call the logic for verifying the text inputs on entry login attempt #
def verifyLogin(sender, app_data):
    # Declare password and pass the input1Password value from login_window #
    password = dpg.get_value(input1Password)

    # Check the length of the password to determine whether or not we show error text #
    if (len(password) == 0):
        dpg.configure_item(lw_inputPassword_error_text_empty, show=True)
        return True
    if (len(password) > 0):
        dpg.configure_item(lw_inputPassword_error_text_empty, show=False)

    # Grab the password from the local db #
    con = sqlite3.connect("devPasswordManager.db")
    cur = con.cursor()
    res = cur.execute("SELECT hash FROM userPasswords WHERE type = 'master'")
    verifyKey = res.fetchone()
    hash_from_db = verifyKey[0]

    # Verify the db hash with the supplied password from login_window #
    ph = PasswordHasher()
    try:
        ph.verify(hash_from_db, password)
        main_window_from_loginWindow()
    except:
        dpg.configure_item(lw_inputPassword_error_text, show=True)
        print("Password is incorrect.")

# Verify the data from the user creation form. #
def verifyCUA():

    # Initialize the values for enabling the logic to proceed or not (bools) #
    password1Verified = False
    password2Verified = False
    cuaVerified = False

    # Initialize the values from cua_inputPassword(Verify) #
    vCUAstr1 = dpg.get_value(cua_inputPassword)
    vCUAstr2 = dpg.get_value(cua_inputPasswordVerify)

    # Convert the values from type "int | str" ---> standalone str for use with computation #
    vCUAstr1 = str(vCUAstr1)
    vCUAstr2 = str(vCUAstr2)

    # If statements to cleanse password & username of illegal characters (because match case statements wouldn't work for this occasion >_>) #
    if (vCUAstr1 == vCUAstr2):
        print("Passwords matched")
        dpg.configure_item(cua_inputPassword_error_text, show=False)
    else:
        dpg.configure_item(cua_inputPassword_error_text, show=True)

    # Cleansing vCUAstr1 (Password1) #
    if (len(vCUAstr1) == 0):
        print("Password1 is empty")
        dpg.configure_item(cua_inputPassword_error_text_empty, show=True)
    
    if (len(vCUAstr1) > 0):
        password1Verified = True
        dpg.configure_item(cua_inputPassword_error_text_empty, show=False)

    # Cleansing vCUAstr2 (Password2) #
    if (len(vCUAstr2) == 0):
        print("Password2 is empty")
        dpg.configure_item(cua_inputPasswordVerify_error_text_empty, show=True)
    
    if (len(vCUAstr2) > 0):
        password2Verified = True
        dpg.configure_item(cua_inputPasswordVerify_error_text_empty, show=False)
    
    # Send to the main window if everything comes back true. #
    if (password1Verified & password2Verified == True):
        hash_and_create_db(vCUAstr1, today)
        main_window_From_CUA()

# Create the window responsible for creating the user accounts if a user account is not present on the filesystem. #
with dpg.window(tag="createUserAccount", show=False) as cua_window:
    dpg.add_text("Welcome to Dev's Password Manager!")
    dpg.add_spacer(height=8)
    dpg.add_text("Please provide the information below to set up the local account of Dev's Password Manager.")
    cua_inputPassword_error_text = dpg.add_text("Your passwords do not match.", color=(255, 0, 0), show=False)
    cua_inputPassword_error_text_empty = dpg.add_text("Your password cannot be empty.", color=(255, 0, 0), show=False)
    cua_inputPassword = dpg.add_input_text(label="Master Password:", password=True)
    cua_inputPasswordVerify_error_text_empty = dpg.add_text("Your password cannot be empty.", color=(255, 0, 0), show=False)
    cua_inputPasswordVerify = dpg.add_input_text(label="Master Password Verification:", password=True)
    dpg.add_button(label="Create Local Account", callback=verifyCUA)
    dpg.add_spacer(height=8)
    # dpg.add_button(label="Back to account login", callback=loginWindow) #

# Create the window responsible for logging in/creating a user account.
with dpg.window(tag="entry", show=False) as login_window:
    dpg.add_spacer(height=8)
    text1 = dpg.add_text("Welcome to Dev's Password Manager! (Login Window)", label="text1")
    dpg.add_spacer(height=8)
    dpg.add_text("Enter your Master password: ")
    lw_inputPassword_error_text = dpg.add_text("The password entered is incorrect.", color=(255, 0, 0), show=False)
    lw_inputPassword_error_text_empty = dpg.add_text("Your password cannot be empty.", color=(255, 0, 0), show=False)
    input1Password = dpg.add_input_text(password=True)
    dpg.add_spacer(height=8)
    dpg.add_button(label="Login", height=25, callback=verifyLogin)



# Create the window responsible for showing the user's saved passwords, ids, accounts, etc.. #

# Create a menu bar at the top of the screen with two items, Login and Create Account. #
    with dpg.window(tag="userHomeScreen", show=False) as main_window:
        spacer = dpg.add_spacer(height=8)
        dpg.add_text("Welcome to the main program!")

   #        with dpg.viewport_menu_bar():
   #            with dpg.menu(label="File"):
   #                dpg.add_menu_item(label="Login")
   #                dpg.add_menu_item(label="Create Account")

dpg.setup_dearpygui()
dpg.show_viewport()
verifyCreatedMasterPassword()
dpg.start_dearpygui()
dpg.destroy_context()