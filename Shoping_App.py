import uuid

# --- Demo Data (In-memory "databases") ---

# Users: username -> password
users_db = {
    "user1": "password1",
    "user2": "password2"
}

# Admins: username -> password
admins_db = {
    "admin": "adminpass"
}

# Categories: category_id -> category_name
categories_db = {
    1: "Boots",
    2: "Coats",
    3: "Jackets",
    4: "Caps"
}

# Products: product_id -> dict with product info
products_db = {
    1: {"name": "Leather Boots", "category_id": 1, "price": 2500},
    2: {"name": "Winter Coat", "category_id": 2, "price": 3500},
    3: {"name": "Denim Jacket", "category_id": 3, "price": 2000},
    4: {"name": "Baseball Cap", "category_id": 4, "price": 500},
}

# Sessions: session_id -> dict with user info and cart (for users) or admin info
sessions = {}

# Helper function to generate session ids
def generate_session_id():
    return str(uuid.uuid4())


# --- Utility Functions ---

def print_welcome():
    print("Welcome to the Demo Marketplace\n")


def verify_user(username, password):
    return users_db.get(username) == password


def verify_admin(username, password):
    return admins_db.get(username) == password


def display_categories():
    print("\nProduct Categories:")
    for cid, cname in categories_db.items():
        print(f"  {cid}. {cname}")


def display_products():
    print("\nProduct Catalog:")
    print(f"{'ID':<5} {'Name':<20} {'Category':<10} {'Price (Rs.)':<10}")
    for pid, pinfo in products_db.items():
        cname = categories_db.get(pinfo["category_id"], "Unknown")
        print(f"{pid:<5} {pinfo['name']:<20} {cname:<10} {pinfo['price']:<10}")


def get_category_by_id(cid):
    return categories_db.get(cid)


def get_product_by_id(pid):
    return products_db.get(pid)


# --- User Functions ---

def user_menu(session_id):
    while True:
        print("\nUser Menu:")
        print("1. View Catalog")
        print("2. View Cart")
        print("3. Add Item to Cart")
        print("4. Remove Item from Cart")
        print("5. Checkout")
        print("6. Logout")

        choice = input("Choose an option: ").strip()
        if choice == "1":
            display_products()

        elif choice == "2":
            view_cart(session_id)

        elif choice == "3":
            add_item_to_cart(session_id)

        elif choice == "4":
            remove_item_from_cart(session_id)

        elif choice == "5":
            checkout(session_id)

        elif choice == "6":
            print("Logging out...")
            sessions.pop(session_id, None)
            break

        else:
            print("Invalid choice, please try again.")


def view_cart(session_id):
    cart = sessions[session_id]["cart"]
    if not cart:
        print("Your cart is empty.")
        return
    print("\nYour Cart:")
    total = 0
    print(f"{'Product ID':<12} {'Name':<20} {'Quantity':<10} {'Price per unit':<15} {'Subtotal':<10}")
    for pid, qty in cart.items():
        product = get_product_by_id(pid)
        if product:
            subtotal = product["price"] * qty
            total += subtotal
            print(f"{pid:<12} {product['name']:<20} {qty:<10} {product['price']:<15} {subtotal:<10}")
    print(f"Total Amount: Rs. {total}")


def add_item_to_cart(session_id):
    try:
        pid = int(input("Enter Product ID to add: "))
        product = get_product_by_id(pid)
        if not product:
            print("Product not found.")
            return
        qty = int(input("Enter quantity: "))
        if qty <= 0:
            print("Quantity must be positive.")
            return

        cart = sessions[session_id]["cart"]
        cart[pid] = cart.get(pid, 0) + qty
        print(f"Added {qty} x {product['name']} to cart.")

    except ValueError:
        print("Invalid input. Please enter numeric values.")


def remove_item_from_cart(session_id):
    try:
        pid = int(input("Enter Product ID to remove: "))
        cart = sessions[session_id]["cart"]
        if pid not in cart:
            print("Product not in cart.")
            return
        qty = int(input("Enter quantity to remove: "))
        if qty <= 0:
            print("Quantity must be positive.")
            return
        if qty >= cart[pid]:
            del cart[pid]
            print("Product removed from cart.")
        else:
            cart[pid] -= qty
            print(f"Removed {qty} units of product from cart.")
    except ValueError:
        print("Invalid input. Please enter numeric values.")


def checkout(session_id):
    cart = sessions[session_id]["cart"]
    if not cart:
        print("Your cart is empty. Cannot checkout.")
        return

    total = sum(products_db[pid]["price"] * qty for pid, qty in cart.items())
    print(f"Total payable amount: Rs. {total}")
    print("Payment Options:")
    print("1. UPI")
    print("2. Debit Card")
    print("3. Net Banking")
    print("4. PayPal")

    choice = input("Select payment method (1-4): ").strip()

    payment_methods = {
        "1": "Unified Payment Interface (UPI)",
        "2": "Debit Card",
        "3": "Net Banking",
        "4": "PayPal"
    }

    if choice not in payment_methods:
        print("Invalid payment option.")
        return

    method = payment_methods[choice]

    if method == "UPI":
        print(f"You will be shortly redirected to the portal for Unified Payment Interface to make a payment of Rs. {total}")
    else:
        print(f"Your order is successfully placed using {method}. Amount paid: Rs. {total}")

    # Clear cart after payment
    sessions[session_id]["cart"].clear()


# --- Admin Functions ---

def admin_menu(session_id):
    while True:
        print("\nAdmin Menu:")
        print("1. View Catalog")
        print("2. Add New Product")
        print("3. Update Existing Product")
        print("4. Remove Product")
        print("5. Add New Category")
        print("6. Remove Category")
        print("7. Logout")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            display_products()

        elif choice == "2":
            add_new_product(session_id)

        elif choice == "3":
            update_existing_product(session_id)

        elif choice == "4":
            remove_product(session_id)

        elif choice == "5":
            add_new_category(session_id)

        elif choice == "6":
            remove_category(session_id)

        elif choice == "7":
            print("Logging out...")
            sessions.pop(session_id, None)
            break

        else:
            print("Invalid choice, please try again.")


def add_new_product(session_id):
    try:
        pname = input("Enter product name: ").strip()
        display_categories()
        cid = int(input("Enter category ID for product: "))
        if cid not in categories_db:
            print("Category does not exist.")
            return
        price = float(input("Enter price: "))
        if price <= 0:
            print("Price must be positive.")
            return

        new_pid = max(products_db.keys()) + 1 if products_db else 1
        products_db[new_pid] = {"name": pname, "category_id": cid, "price": price}
        print(f"Product '{pname}' added successfully with ID {new_pid}.")

    except ValueError:
        print("Invalid input. Please enter numeric values for category and price.")


def update_existing_product(session_id):
    try:
        pid = int(input("Enter product ID to update: "))
        product = get_product_by_id(pid)
        if not product:
            print("Product not found.")
            return

        print(f"Current details: Name: {product['name']}, Category ID: {product['category_id']}, Price: {product['price']}")
        pname = input("Enter new product name (leave blank to keep current): ").strip()
        display_categories()
        cid_input = input("Enter new category ID (leave blank to keep current): ").strip()
        price_input = input("Enter new price (leave blank to keep current): ").strip()

        if pname:
            product['name'] = pname
        if cid_input:
            cid = int(cid_input)
            if cid in categories_db:
                product['category_id'] = cid
            else:
                print("Category does not exist. Keeping previous category.")
        if price_input:
            price = float(price_input)
            if price > 0:
                product['price'] = price
            else:
                print("Invalid price. Keeping previous price.")

        print("Product updated successfully.")

    except ValueError:
        print("Invalid input. Please enter numeric values where required.")


def remove_product(session_id):
    try:
        pid = int(input("Enter product ID to remove: "))
        if pid not in products_db:
            print("Product not found.")
            return
        removed_product = products_db.pop(pid)
        print(f"Product '{removed_product['name']}' removed from catalog.")

    except ValueError:
        print("Invalid input. Please enter a valid product ID.")


def add_new_category(session_id):
    cname = input("Enter new category name: ").strip()
    if not cname:
        print("Category name cannot be empty.")
        return
    if cname in categories_db.values():
        print("Category already exists.")
        return
    new_cid = max(categories_db.keys()) + 1 if categories_db else 1
    categories_db[new_cid] = cname
    print(f"Category '{cname}' added successfully with ID {new_cid}.")


def remove_category(session_id):
    try:
        display_categories()
        cid = int(input("Enter category ID to remove: "))
        if cid not in categories_db:
            print("Category not found.")
            return

        # Check if any product belongs to this category
        in_use = any(p["category_id"] == cid for p in products_db.values())
        if in_use:
            print("Cannot remove category because some products belong to it. Remove or reassign those products first.")
            return

        removed_cat = categories_db.pop(cid)
        print(f"Category '{removed_cat}' removed successfully.")

    except ValueError:
        print("Invalid input. Please enter a valid category ID.")


# --- Main Login and Routing Logic ---

def main():
    print_welcome()
    while True:
        print("\nLogin Menu:")
        print("1. User Login")
        print("2. Admin Login")
        print("3. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            if verify_user(username, password):
                session_id = generate_session_id()
                sessions[session_id] = {"role": "user", "username": username, "cart": {}}
                print(f"User '{username}' logged in successfully. Session ID: {session_id}")
                user_menu(session_id)
            else:
                print("Invalid user credentials.")

        elif choice == "2":
            username = input("Enter admin username: ").strip()
            password = input("Enter admin password: ").strip()
            if verify_admin(username, password):
                session_id = generate_session_id()
                sessions[session_id] = {"role": "admin", "username": username}
                print(f"Admin '{username}' logged in successfully. Session ID: {session_id}")
                admin_menu(session_id)
            else:
                print("Invalid admin credentials. Access denied.")

        elif choice == "3":
            print("Exiting Demo Marketplace. Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
