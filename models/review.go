package models

type Review struct {
	ID         int    `json:"id"`
	UserID     int    `json:"user_id"`
	MenuItemID int    `json:"menu_item_id"`
	Rating     int    `json:"rating"`
	Comment    string `json:"comment"`
	CreatedAt  string `json:"created_at"`
}
