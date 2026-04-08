package models

type Order struct {
	ID        int         `json:"id"`
	UserID    int         `json:"user_id"`
	Total     float64     `json:"total"`
	Status    string      `json:"status"`
	Note      string      `json:"note"`
	Items     []OrderItem `json:"items,omitempty"`
	CreatedAt string      `json:"created_at"`
}

type OrderItem struct {
	ID         int     `json:"id"`
	OrderID    int     `json:"order_id"`
	MenuItemID int     `json:"menu_item_id"`
	Quantity   int     `json:"quantity"`
	Price      float64 `json:"price"`
}
