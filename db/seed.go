package db

import (
	"log"
)

func Seed() {
	seedUsers()
	seedMenuItems()
	seedInventory()
	seedOrders()
	seedReviews()
	seedFiles()
}

func seedUsers() {
	users := []struct {
		username, email, password, role string
	}{
		{"admin", "admin@thelocalplate.com", "Admin@2024!", "admin"},
		{"alice", "alice@example.com", "Password123", "user"},
		{"bob", "bob@example.com", "Qwerty456", "user"},
		{"carol", "carol@example.com", "Secret789", "user"},
		{"dave", "dave@example.com", "Dave1234", "user"},
	}

	stmt := `INSERT OR IGNORE INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)`
	for i, u := range users {
		if _, err := DB.Exec(stmt, i+1, u.username, u.email, u.password, u.role); err != nil {
			log.Printf("seed user error: %v", err)
		}
	}
}

func seedMenuItems() {
	items := []struct {
		id                   int
		name, desc, cat, img string
		price                float64
	}{
		{1, "Margherita Pizza", "Classic Neapolitan pizza with San Marzano tomatoes, fresh mozzarella, and basil.", "Pizza", "/static/assets/img/pizza.jpg", 14.99},
		{2, "Pepperoni Feast", "Loaded with premium pepperoni, mozzarella, and house tomato sauce.", "Pizza", "/static/assets/img/pizza2.jpg", 17.99},
		{3, "Truffle Mushroom Risotto", "Creamy Arborio rice with wild mushrooms and black truffle oil.", "Pasta", "/static/assets/img/risotto.jpg", 19.99},
		{4, "Grilled Salmon", "Atlantic salmon fillet with lemon herb butter and seasonal vegetables.", "Mains", "/static/assets/img/salmon.jpg", 24.99},
		{5, "Caesar Salad", "Crisp romaine, shaved parmesan, croutons, and classic Caesar dressing.", "Salads", "/static/assets/img/salad.jpg", 11.99},
		{6, "Wagyu Beef Burger", "8oz wagyu patty, aged cheddar, caramelized onions on brioche bun.", "Burgers", "/static/assets/img/burger.jpg", 22.99},
		{7, "Tiramisu", "Authentic Italian dessert with espresso-soaked ladyfingers and mascarpone.", "Desserts", "/static/assets/img/tiramisu.jpg", 8.99},
		{8, "Lobster Bisque", "Rich, creamy bisque made with fresh Atlantic lobster.", "Soups", "/static/assets/img/bisque.jpg", 13.99},
		{9, "Bruschetta al Pomodoro", "Toasted sourdough with heirloom tomatoes, garlic, and extra virgin olive oil.", "Starters", "/static/assets/img/bruschetta.jpg", 9.99},
		{10, "Chocolate Lava Cake", "Warm chocolate cake with a molten center, served with vanilla gelato.", "Desserts", "/static/assets/img/lavacake.jpg", 9.99},
	}

	stmt := `INSERT OR IGNORE INTO menu_items (id, name, description, price, category, image_url, available) VALUES (?, ?, ?, ?, ?, ?, 1)`
	for _, item := range items {
		if _, err := DB.Exec(stmt, item.id, item.name, item.desc, item.price, item.cat, item.img); err != nil {
			log.Printf("seed menu error: %v", err)
		}
	}
}

func seedOrders() {
	orders := []struct {
		id, userID int
		total      float64
		status     string
		note       string
	}{
		{1, 2, 32.98, "completed", "Extra napkins please"},
		{2, 2, 14.99, "completed", ""},
		{3, 3, 44.98, "completed", ""},
		{4, 3, 19.99, "preparing", "No mushrooms"},
		{5, 4, 24.99, "pending", ""},
		{6, 4, 26.98, "completed", ""},
		{7, 5, 9.99, "completed", ""},
		{8, 5, 47.97, "cancelled", "Change of mind"},
		{9, 2, 22.99, "completed", ""},
		{10, 3, 13.99, "completed", ""},
	}

	oStmt := `INSERT OR IGNORE INTO orders (id, user_id, total, status, note, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', '-' || ? || ' days'))`
	oiStmt := `INSERT OR IGNORE INTO order_items (order_id, menu_item_id, quantity, price) VALUES (?, ?, ?, ?)`

	orderItems := map[int][][]interface{}{
		1:  {{1, 1, 14.99}, {6, 1, 22.99}},
		2:  {{1, 1, 14.99}},
		3:  {{4, 1, 24.99}, {6, 1, 22.99}},
		4:  {{3, 1, 19.99}},
		5:  {{4, 1, 24.99}},
		6:  {{5, 1, 11.99}, {9, 1, 9.99}, {7, 1, 8.99}},
		7:  {{9, 1, 9.99}},
		8:  {{10, 1, 9.99}, {8, 1, 13.99}, {4, 1, 24.99}},
		9:  {{6, 1, 22.99}},
		10: {{8, 1, 13.99}},
	}

	for _, o := range orders {
		day := 30 - o.id*2
		if _, err := DB.Exec(oStmt, o.id, o.userID, o.total, o.status, o.note, day); err != nil {
			log.Printf("seed order error: %v", err)
		}
		for _, item := range orderItems[o.id] {
			DB.Exec(oiStmt, o.id, item[0], item[1], item[2])
		}
	}
}

func seedInventory() {
	items := []struct {
		menuItemID int
		stock      int
		location   string
	}{
		{1, 2, "main-kitchen"},
		{2, 3, "main-kitchen"},
		{3, 4, "prep-station"},
		{4, 2, "cold-room"},
		{5, 6, "salad-pass"},
		{6, 1, "grill-line"},
		{7, 5, "pastry"},
		{8, 3, "soup-kettle"},
		{9, 4, "starter-pass"},
		{10, 5, "pastry"},
	}

	stmt := `INSERT OR IGNORE INTO inventory (menu_item_id, stock, location) VALUES (?, ?, ?)`
	for _, item := range items {
		if _, err := DB.Exec(stmt, item.menuItemID, item.stock, item.location); err != nil {
			log.Printf("seed inventory error: %v", err)
		}
	}
}

func seedReviews() {
	reviews := []struct {
		id, userID, menuItemID, rating int
		comment                        string
	}{
		{1, 2, 1, 5, "Absolutely delicious! Best pizza I've had outside of Naples."},
		{2, 3, 1, 4, "Great pizza, slightly over-baked but still amazing."},
		{3, 4, 3, 5, "The risotto is divine. Truffle flavor was spot on."},
		{4, 5, 4, 4, "Salmon was cooked perfectly. Will come back."},
		{5, 2, 6, 5, "Best burger in town. The wagyu is worth every penny."},
		{6, 3, 7, 5, "Most authentic tiramisu I've ever tasted!"},
		{7, 4, 8, 4, "Rich and creamy bisque, great for a cold evening."},
		{8, 5, 9, 3, "Good bruschetta but the tomatoes could be fresher."},
		{9, 2, 10, 5, "The lava cake is heavenly. Paired beautifully with the gelato."},
		{10, 3, 2, 4, "Pepperoni was plentiful and crispy. Enjoyed it very much."},
	}

	stmt := `INSERT OR IGNORE INTO reviews (id, user_id, menu_item_id, rating, comment, created_at) VALUES (?, ?, ?, ?, ?, datetime('now', '-' || ? || ' days'))`
	for _, r := range reviews {
		if _, err := DB.Exec(stmt, r.id, r.userID, r.menuItemID, r.rating, r.comment, r.id); err != nil {
			log.Printf("seed review error: %v", err)
		}
	}
}

func seedFiles() {
	files := []struct {
		id         int
		name, path string
		uploadedBy int
	}{
		{1, "menu_export.csv", "uploads/menu_export.csv", 1},
		{2, "specials.txt", "uploads/specials.txt", 1},
	}

	stmt := `INSERT OR IGNORE INTO files (id, name, path, uploaded_by) VALUES (?, ?, ?, ?)`
	for _, f := range files {
		DB.Exec(stmt, f.id, f.name, f.path, f.uploadedBy)
	}
}
