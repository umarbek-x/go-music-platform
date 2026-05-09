package modules

type RegisterResponse struct {
	Id       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Lastname string `json:"lastname,omitempty"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role,omitempty"`
}
