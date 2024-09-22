import customtkinter as ctk
from tkinter import filedialog, messagebox, Canvas, Scrollbar
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from create_database import User, Artwork, Base
from cryptography.exceptions import InvalidSignature
from customtkinter import CTkImage
import os
import uuid
import json



# Database setup
engine = create_engine('sqlite:///das_app.db')
Session = sessionmaker(bind=engine)
session = Session()

class DASApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Set the window title
        self.title("Digital Art Signature")
        
        # Set the initial window size
        self.geometry("860x530")
        self.minsize(860, 530)

        
        # Set the background color of the app window
        self.configure(bg="#2b2b2b")

        #icon for the app
        self.iconbitmap("assets/signature.ico")
        
        # Placeholder to store the current visible frame (for switching between frames)
        self.current_frame = None
        
        # Placeholder to store the logged-in user (initialized as None until login)
        self.user = None
        
        # Call to set up the initial UI by showing the welcome page
        self.setup_ui()

    def setup_ui(self):
        # Check if the token file exists (this file stores the 'Remember Me' token)
        if os.path.exists('token.txt'):
            with open('token.txt', 'r') as file:
                username = file.read().strip()
                user = session.query(User).filter_by(username=username).first()
                if user:
                    self.user = user
                    self.show_main_app()  # Auto-login and show main app
                    return
        
        # Show welcome page if no token is found
        self.show_welcome_page()

    def switch_frame(self, new_frame):
        # Method to switch between different frames (pages) in the app
        # If a frame is already displayed, destroy it (remove from view)
        if self.current_frame is not None:
            self.current_frame.destroy()
        
        # Set the new frame to be displayed
        self.current_frame = new_frame
        
        # Add padding and expand options to make the new frame take up available space
        self.current_frame.pack(pady=20, padx=60, fill="both", expand=True)

    def show_welcome_page(self):
        # Create a new frame for the welcome page
        self.welcome_frame = ctk.CTkFrame(self, fg_color="#242424")  # Main background color
        self.welcome_frame.pack(expand=True, padx=20, pady=20)

        # Switch to the welcome frame (display it)
        self.switch_frame(self.welcome_frame)

        # Create a main container frame to hold everything
        main_container = ctk.CTkFrame(self.welcome_frame, fg_color="#242424", corner_radius=15)
        main_container.pack(expand=True, fill="both", padx=3, pady=3)

        # Create left and right frames for layout
        left_frame = ctk.CTkFrame(main_container, fg_color="#4b4b4b")
        left_frame.pack(side="left", fill="y", padx=(10, 5) )

        right_frame = ctk.CTkFrame(main_container, fg_color="#4b4b4b")
        right_frame.pack(side="right", fill="both", expand=True, padx=(5, 1))

        # Add the title label to the left frame (centered)
        self.label_title = ctk.CTkLabel(right_frame, text="Digital Art Signature", font=("Arial", 30), text_color="#ffffff")
        self.label_title.pack(pady=(50, 0), padx=10)  # Add padding around the label

        # Add the title label to the left frame (centered)
        self.label_welcome = ctk.CTkLabel(left_frame, text="Welcome!", font=("Ariel", 30), text_color="#ffffff")
        self.label_welcome.pack(pady=(50, 0), padx=10)  # Add padding around the label

        # Create a squared card layout for buttons
        button_card = ctk.CTkFrame(left_frame, fg_color="#4b4b4b", width=250, height=250, corner_radius=10)
        button_card.pack(expand=True, padx=10, pady=(0, 50))

        # Add a 'Login' button to the card
        self.login_button = ctk.CTkButton(button_card, text="Login", command=self.show_login_page, corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
        self.login_button.pack(pady=(10, 5), padx=20)  # Add padding around the button

        # Add a 'Register' button to the card
        self.register_button = ctk.CTkButton(button_card, text="Register", command=self.show_register_page, corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
        self.register_button.pack(pady=(5, 10), padx=20)  # Add padding around the button

        # Description text
        description_text = "Welcome to Digital Art Signature.\nThis app allows you to register, upload, sign,\nand view your artworks securely."
        self.label_description = ctk.CTkLabel(right_frame, text=description_text, font=("Arial", 17), fg_color="#4b4b4b", justify="center")
        self.label_description.pack(expand=True, padx=20, pady=(0, 70))  # Centered and padding for aesthetics

    def make_square(self, frame):
        # Make the frame square based on its width
        width = frame.winfo_width()
        frame.config(height=width)  # Set the height to match the width

    def show_login_page(self):
        # Create a new frame for the login page
        self.login_frame = ctk.CTkFrame(self, fg_color="#3b3b3b")  # Frame with a custom background color
        
        # Switch to the login frame (display it)
        self.switch_frame(self.login_frame)
        
        self.label_r = ctk.CTkLabel(self.login_frame, text="Login", font=("Arial", 29))
        self.label_r.pack(pady=(20, 0), padx=10)  # Add padding around the label

        # Add a label for the username input field
        self.label_username = ctk.CTkLabel(self.login_frame, text="Username:", font=("Arial", 14))
        self.label_username.pack(pady=(25, 0), padx=10)  # Add padding around the label

        # Create an entry widget for the user to input their username
        self.entry_username = ctk.CTkEntry(self.login_frame)
        self.entry_username.pack(pady=(0, 10), padx=10)  # Add padding around the entry

        # Add a label for the password input field
        self.label_password = ctk.CTkLabel(self.login_frame, text="Password:", font=("Arial", 14))
        self.label_password.pack(pady=(10, 0), padx=10)  # Add padding around the label

        # Create an entry widget for the user to input their password, with hidden text (show="*")
        self.entry_password = ctk.CTkEntry(self.login_frame, show="•")
        self.entry_password.pack(pady=(0, 20), padx=10)  # Add padding around the entry

        # Add "Remember Me" checkbox
        self.check_remember_me = ctk.BooleanVar()
        remember_me_checkbox = ctk.CTkCheckBox(self.login_frame, text="Remember Me", variable=self.check_remember_me)
        remember_me_checkbox.pack(pady=(0, 20), padx=10)

        # Add a 'Login' button to submit the login form
        self.button_login = ctk.CTkButton(self.login_frame, text="Login", command=self.login, corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
        self.button_login.pack(pady=10, padx=10)  # Add padding around the button

        # Add a 'Back' button to return to the welcome page
        self.button_back = ctk.CTkButton(self.login_frame, text="Back", command=self.show_welcome_page, corner_radius=10, fg_color="#ff6347", hover_color="#ff4500")
        self.button_back.pack(pady=10, padx=10)  # Add padding around the button

        # Add a label to display login result messages (e.g., success or error)
        self.label_result = ctk.CTkLabel(self.login_frame, text="", font=("Arial", 14))
        self.label_result.pack(pady=10, padx=10)  # Add padding around the label

    def show_register_page(self):
        # Create a new frame for the registration page
        self.register_frame = ctk.CTkFrame(self, fg_color="#3b3b3b")  # Frame with a custom background color

        # Switch to the registration frame (display it)
        self.switch_frame(self.register_frame)

        self.label_r = ctk.CTkLabel(self.register_frame, text="Register", font=("Arial", 29))
        self.label_r.pack(pady=(10, 0), padx=10)  # Add padding around the label

        # Add a label for the username input field
        self.label_username = ctk.CTkLabel(self.register_frame, text="Username:", font=("Arial", 14))
        self.label_username.pack(pady=(20, 0), padx=10)  # Add padding around the label

        # Create an entry widget for the user to input their desired username
        self.entry_username = ctk.CTkEntry(self.register_frame)
        self.entry_username.pack(pady=(0, 10), padx=10)  # Add padding around the entry

        # Add a label for the password input field
        self.label_password = ctk.CTkLabel(self.register_frame, text="Password:", font=("Arial", 14))
        self.label_password.pack(pady=(10, 0), padx=10)  # Add padding around the label

        # Create an entry widget for the user to input their password, with hidden text (show="*")
        self.entry_password = ctk.CTkEntry(self.register_frame, show="•")
        self.entry_password.pack(pady=(0, 10), padx=10)  # Add padding around the entry

        # Add a label for the confirm password input field
        self.label_confirm_password = ctk.CTkLabel(self.register_frame, text="Confirm Password:", font=("Arial", 14))
        self.label_confirm_password.pack(pady=(10, 0), padx=10)  # Add padding around the label

        # Create an entry widget for the user to confirm their password, with hidden text (show="*")
        self.entry_confirm_password = ctk.CTkEntry(self.register_frame, show="•")
        self.entry_confirm_password.pack(pady=(0, 10), padx=10)  # Add padding around the entry

        # Create a frame for the buttons
        button_frame = ctk.CTkFrame(self.register_frame, fg_color="#3b3b3b")
        button_frame.pack(pady=(20, 0), padx=10)

        # Add a 'Register' button to submit the registration form
        self.button_register = ctk.CTkButton(button_frame, text="Register", command=self.register, corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
        self.button_register.pack(side="left", padx=(0, 20))  # Add padding to the right

        # Add a 'Back' button to return to the welcome page
        self.button_back = ctk.CTkButton(button_frame, text="Back", command=self.show_welcome_page, corner_radius=10, fg_color="#ff6347", hover_color="#ff4500")
        self.button_back.pack(side="left")  # No extra padding needed


        # Add a label to display registration result messages (e.g., success or error)
        self.label_result = ctk.CTkLabel(self.register_frame, text="", font=("Arial", 14))
        self.label_result.pack(pady=10, padx=10)  # Add padding around the label

    def show_main_app(self):
        # Create the main application frame
        self.main_frame = ctk.CTkFrame(self, fg_color="#3b3b3b")  # Frame with a custom background color
        self.switch_frame(self.main_frame)  # Switch to the main application frame
        
        # Create a top frame for welcome message and logout button
        top_frame = ctk.CTkFrame(self.main_frame, fg_color="#3b3b3b")
        top_frame.pack(fill="x")  # Fill the top frame horizontally

        # Display a welcome message with the username
        self.label_welcome = ctk.CTkLabel(top_frame, text=f"Welcome, {self.user.username}!", font=("Arial", 24))
        self.label_welcome.pack(side="left", pady=20, padx=30)  # Position the label on the left

        # Add a logout button to return to the welcome page
        self.logout_button = ctk.CTkButton(top_frame, text="Logout", command=self.logout, corner_radius=10, fg_color="#ff6347", hover_color="#ff4500")
        self.logout_button.pack(side="right", pady=10, padx=30)  # Position the button on the right

        # Add a button to upload artwork
        self.upload_button = ctk.CTkButton(self.main_frame, text="Upload Artwork", command=self.upload_artwork, corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
        self.upload_button.pack(pady=10, padx=20)  # Center the button with padding

        # Add a button to sign artwork
        self.sign_button = ctk.CTkButton(self.main_frame, text="Sign Artwork", command=self.sign_artwork, corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
        self.sign_button.pack(pady=10, padx=20)  # Center the button with padding

        # Add a button to view uploaded artworks
        self.view_button = ctk.CTkButton(self.main_frame, text="View Artworks", command=self.view_artworks, corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
        self.view_button.pack(pady=10, padx=20)  # Center the button with padding

    def upload_artwork(self):
        # Open a file dialog to select artwork for upload
        file_path = filedialog.askopenfilename()
        if file_path:  # Check if a file was selected
            artwork_name = os.path.basename(file_path)  # Get the name of the artwork file
            # Check if the artwork has already been uploaded by the user
            existing_artwork = session.query(Artwork).filter_by(user_id=self.user.id, path=file_path).first()
            if existing_artwork:
                # Show an error message if the artwork is already uploaded
                messagebox.showerror("Error", "This artwork has already been uploaded.")
            else:
                # Create a new Artwork instance and add it to the database
                new_artwork = Artwork(user_id=self.user.id, name=artwork_name, path=file_path)
                session.add(new_artwork)  # Add the new artwork to the session
                session.commit()  # Commit the transaction to save the artwork
                messagebox.showinfo("Success", "Artwork uploaded successfully")  # Show success message

    def sign_artwork(self):
        # Retrieve all artworks uploaded by the user
        artworks = session.query(Artwork).filter_by(user_id=self.user.id).all()
        # Filter out artworks that have already been signed
        unsigned_artworks = [artwork for artwork in artworks if not artwork.signature]
        
        if not unsigned_artworks:
            # Inform the user if all artworks are already signed
            messagebox.showinfo("Info", "All artworks are already signed")
            return  # Exit the method if there are no unsigned artworks

        # Sign each unsigned artwork
        for artwork in unsigned_artworks:
            # Generate a new DSA private key
            private_key = dsa.generate_private_key(key_size=2048)
            public_key = private_key.public_key()  # Extract the corresponding public key

            # Create a signature for the artwork's path using SHA-256
            signature = private_key.sign(
                artwork.path.encode(),
                hashes.SHA256()
            )

            # Store the signature and the public key (both in appropriate formats)
            artwork.signature = signature.hex()  # Store the signature as a hexadecimal string
            artwork.public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')  # Store the public key as a PEM formatted string

            # Commit the transaction to save the signature and public key to the database
            session.commit()
            
            messagebox.showinfo("Success", f"Artwork '{artwork.name}' signed successfully")  # Show success message
            return  # Exit after signing the first unsigned artwork

    def view_artworks(self):
        # Create a frame for viewing artworks
        self.view_frame = ctk.CTkFrame(self, fg_color="#3b3b3b")  # Frame with a custom background color
        self.switch_frame(self.view_frame)  # Switch to the artworks viewing frame

        # Add a back button to return to the main app
        button_back = ctk.CTkButton(self.view_frame, text="Back", command=self.show_main_app, corner_radius=10, fg_color="#ff6347", hover_color="#ff4500")
        button_back.pack(pady=10, side="bottom", anchor="center")  # Position the button at the bottom center

        # Create a canvas and a scrollbar for displaying and scrolling the artwork list
        canvas = ctk.CTkCanvas(self.view_frame, bg="#3b3b3b", highlightthickness=0)  # Canvas for artwork display
        scrollbar = ctk.CTkScrollbar(self.view_frame, orientation="vertical", command=canvas.yview)  # Vertical scrollbar
        scrollable_frame = ctk.CTkFrame(canvas, fg_color="#3b3b3b")  # Frame to hold the artworks

        # Bind the scrollable frame to the canvas for scrolling functionality
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")  # Update the scroll region to the size of the scrollable frame
            )
        )

        # Create a window in the canvas to hold the scrollable frame
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")  # Position the frame in the canvas
        canvas.configure(yscrollcommand=scrollbar.set)  # Link the scrollbar with the canvas

        # Place the canvas and scrollbar in the view frame
        canvas.pack(side="left", fill="both", expand=True)  # Fill the left side of the view frame
        scrollbar.pack(side="right", fill="y")  # Fill the right side of the view frame

        # Retrieve and display the artworks uploaded by the user
        artworks = session.query(Artwork).filter_by(user_id=self.user.id).all()  # Query artworks for the user
        for artwork in artworks:
            # Create a frame for each artwork
            frame = ctk.CTkFrame(scrollable_frame, fg_color="#3b3b3b")  # Artwork display frame
            frame.pack(pady=5, padx=10, fill="x")  # Position the frame with padding

            # Create a button to show artwork details, passing the artwork object
            button_artwork = ctk.CTkButton(frame, text=f"Name: {artwork.name} | Path: {artwork.path}", command=lambda a=artwork: self.show_artwork_details(a), corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
            button_artwork.pack(side="left", pady=5, padx=5)  # Position the button on the left

            # Create a delete button for the artwork, passing the artwork object
            button_delete = ctk.CTkButton(frame, text="Delete", command=lambda a=artwork: self.delete_artwork(a),corner_radius=10, fg_color="#ff6347", hover_color="#ff4500")
            button_delete.pack(side="right", padx=(60, 0))  # Position the delete button on the right

    def show_artwork_details(self, artwork):
        # Create a frame for showing artwork details
        self.details_frame = ctk.CTkFrame(self, fg_color="#3b3b3b")
        self.switch_frame(self.details_frame)  # Switch to the details frame

        # Display the artwork's name
        label_name = ctk.CTkLabel(self.details_frame, text=f"Name: {artwork.name}", font=("Arial", 14))
        label_name.pack(pady=10, padx=10)  # Add some padding around the label

        # Display the artwork's path
        label_path = ctk.CTkLabel(self.details_frame, text=f"Path: {artwork.path}", font=("Arial", 14))
        label_path.pack(pady=10, padx=10)

        # Load and display the artwork image
        img = Image.open(artwork.path)  # Open the image using its path
        original_width, original_height = img.size

        # Calculate the new width to maintain the aspect ratio
        new_height = 150
        new_width = int((new_height / original_height) * original_width)

        # Resize the image
        img = img.resize((new_width, new_height), Image.LANCZOS)  # Use LANCZOS for better quality
        ctk_img = CTkImage(light_image=img, dark_image=img, size=(new_width, new_height))  # Create a CTkImage
        label_image = ctk.CTkLabel(self.details_frame, image=ctk_img, text="")  # Add image to the label
        label_image.pack(pady=10, padx=10)


        # Create a frame for displaying the signature
        signature_frame = ctk.CTkFrame(self.details_frame)
        signature_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Label for the signature section
        label_signature_title = ctk.CTkLabel(signature_frame, text="Signature:", font=("Arial", 14))
        label_signature_title.pack(pady=0, padx=10, anchor="w")  # Align text to the left (west)

        # Display the artwork's digital signature in a disabled text box
        text_signature = ctk.CTkTextbox(signature_frame, width=600, height=50, wrap="word")

        # Only insert the signature if it exists
        if artwork.signature:
            text_signature.insert("1.0", artwork.signature)  # Insert the signature into the text box
        else:
            text_signature.insert("1.0", "No signature available.")  # Show a message when no signature exists

        text_signature.configure(state="disabled")  # Disable editing
        text_signature.pack(pady=5, padx=10, fill="both", expand=True)

        # Verify the signature and display a message
        if artwork.signature and artwork.public_key:
            if self.verify_signature(artwork):
                label_verification = ctk.CTkLabel(signature_frame, text="Signature is valid", text_color="green", font=("Arial", 14))
            else:
                label_verification = ctk.CTkLabel(signature_frame, text="Signature is not valid", text_color="red", font=("Arial", 14))
            label_verification.pack(pady=5, padx=10)  # Display the verification message
        else:
            label_no_signature = ctk.CTkLabel(signature_frame, text="No signature available for verification.", font=("Arial", 14))
            label_no_signature.pack(pady=5, padx=10)

        # Bottom frame for action buttons
        bot_frame = ctk.CTkFrame(self.details_frame, fg_color="#3b3b3b")
        bot_frame.pack(fill="x")  # Expand horizontally

        # Check if artwork has a signature
        if artwork.signature:
            # Button to export the signature if it exists
            button_export = ctk.CTkButton(bot_frame, text="Export Signature", command=lambda: self.export_signature(artwork), corner_radius=10, fg_color="#1e90ff", hover_color="#1c86ee")
            button_export.pack(side="left", pady=10, padx=100)  # Place on the left with padding

        # Back button to return to the artwork list (always visible)
        button_back = ctk.CTkButton(bot_frame, text="Back", command=self.view_artworks, corner_radius=10, fg_color="#ff6347", hover_color="#ff4500")
        button_back.pack(side="right", pady=10, padx=100)  # Place on the right with padding

    def export_signature(self, artwork):
        # Open a file dialog to choose the location and name for saving the signature
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:  # Check if a valid file path was chosen
            with open(file_path, "w") as sig_file:  # Open the file in write mode
                sig_file.write(artwork.signature)  # Write the signature to the file
            messagebox.showinfo("Success", "Signature exported successfully")  # Notify the user

    def delete_artwork(self, artwork):
        session.delete(artwork)  # Delete the selected artwork from the database
        session.commit()  # Commit the changes to the database
        messagebox.showinfo("Success", "Artwork deleted successfully")  # Notify the user
        self.view_artworks()  # Refresh the artwork list

    def register(self):
        # Get user input for registration
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        confirm_password = self.entry_confirm_password.get().strip()

        # Validate input fields
        if not username:
            self.label_result.configure(text="Username cannot be empty")
            return
        if not password:
            self.label_result.configure(text="Password cannot be empty")
            return
        if not confirm_password:
            self.label_result.configure(text="Please confirm your password")
            return
        
        # Check if passwords match
        if password != confirm_password:
            self.label_result.configure(text="Passwords do not match")
            return

        # Check for password strength (length, characters, etc.)
        if len(password) < 8:
            self.label_result.configure(text="Password must be at least 8 characters long")
            return
        if not any(char.isdigit() for char in password):
            self.label_result.configure(text="Password must contain at least one number")
            return
        if not any(char.isupper() for char in password):
            self.label_result.configure(text="Password must contain at least one uppercase letter")
            return

        # Check if the username is already taken
        if session.query(User).filter_by(username=username).first():
            self.label_result.configure(text="Username already exists")
            return

        # Hash the password for secure storage
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create a new user and add to the database
        new_user = User(username=username, password_hash=password_hash.decode('utf-8'))
        session.add(new_user)
        session.commit()  # Commit the changes to the database
        self.label_result.configure(text="User registered successfully")  # Notify the user

    def login(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        remember_me = self.check_remember_me.get()  # Get the value of the checkbox


        if not username:
            self.label_result.configure(text="Username cannot be empty")
            return
        if not password:
            self.label_result.configure(text="Password cannot be empty")
            return

        # Query the database for the user
        user = session.query(User).filter_by(username=username).first()

        # Verify password
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            self.user = user  # Store the user object for later use
            self.label_result.configure(text="Login successful")  # Notify the user
            self.show_main_app()  # Switch to the main application interface
            
            # If "Remember Me" is checked, store the token
            if remember_me:
                with open('token.txt', 'w') as file:
                    file.write(user.username)  # Save the username as a token
        else:
            self.label_result.configure(text="Invalid username or password")  # Notify of failed login

    def verify_signature(self, artwork):
        try:
            # Load the public key from the artwork (PEM format)
            public_key = serialization.load_pem_public_key(artwork.public_key.encode('utf-8'))

            # Verify the signature using the public key and SHA-256
            public_key.verify(
                bytes.fromhex(artwork.signature),  # The signature (converted from hex)
                artwork.path.encode(),  # The data that was signed (the artwork path)
                hashes.SHA256()  # The hash algorithm used during signing
            )
            return True  # If verification passes, return True
        except (InvalidSignature, ValueError):
            return False  # If verification fails, return False

    def logout(self):
        # Delete the token file if it exists
        if os.path.exists('token.txt'):
            os.remove('token.txt')

        # Go back to the welcome page
        self.setup_ui()

# Run the application
if __name__ == "__main__":
    app = DASApp()  # Create an instance of the app
    app.mainloop()  # Start the main event loop
