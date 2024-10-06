package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func connectDB() {
	connStr := "user=postgres password=00000 dbname=optsales_1 port=5433 sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Не удалось подключиться к БД: ", err)
	}
	fmt.Println("Успешное подключение к БД!")
}

func login(w http.ResponseWriter, r *http.Request) {
	var input LoginInput
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var storedHash string
	var role string
	err = db.QueryRow("SELECT password_hash, role FROM users WHERE username = $1", input.Username).Scan(&storedHash, &role)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(input.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: input.Username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	response := struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}{
		Token: tokenString,
		Role:  role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenStr = tokenStr[len("Bearer "):]

		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if !tkn.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	connectDB()

	r := mux.NewRouter()

	r.HandleFunc("/login", login).Methods("POST")

	r.Handle("/goods", authenticate(http.HandlerFunc(getGoods))).Methods("GET")
	r.Handle("/top_goods", authenticate(http.HandlerFunc(getTopGoods))).Methods("GET")
	r.Handle("/demand_change", authenticate(http.HandlerFunc(getDemandChange))).Methods("GET")

	r.Handle("/forecast_demand", authenticate(http.HandlerFunc(forecastDemand))).Methods("GET")
	r.Handle("/goods-for-transfer", authenticate(http.HandlerFunc(getGoodsForTransfer))).Methods("GET")

	r.Handle("/warehouse_counts", authenticate(http.HandlerFunc(getWarehouseCounts))).Methods("GET")
	r.Handle("/sales_counts", authenticate(http.HandlerFunc(getSalesCounts))).Methods("GET")
	r.Handle("/transfer-goods", authenticate(http.HandlerFunc(transferGoods))).Methods("POST")

	r.Handle("/goods1", authenticate(http.HandlerFunc(getGoods1))).Methods("GET")         // Получить все товары
	r.Handle("/goods", authenticate(http.HandlerFunc(addGood))).Methods("POST")           // Добавить новый товар
	r.Handle("/goods/{id}", authenticate(http.HandlerFunc(updateGood))).Methods("PUT")    // Обновить товар по ID
	r.Handle("/goods/{id}", authenticate(http.HandlerFunc(deleteGood))).Methods("DELETE") // Удалить товар по ID

	r.Handle("/sales", authenticate(http.HandlerFunc(getSales))).Methods("GET")           // Получить все заявки
	r.Handle("/sales", authenticate(http.HandlerFunc(addSale))).Methods("POST")           // Добавить новую заявку
	r.Handle("/sales/{id}", authenticate(http.HandlerFunc(updateSale))).Methods("PUT")    // Обновить заявку по ID
	r.Handle("/sales/{id}", authenticate(http.HandlerFunc(deleteSale))).Methods("DELETE") // Удалить заявку по ID

	r.Handle("/wh1", authenticate(http.HandlerFunc(getGoodsWH1))).Methods("GET")
	r.Handle("/wh1", authenticate(http.HandlerFunc(addGoodsWH1))).Methods("POST")
	r.Handle("/wh1/{id}", authenticate(http.HandlerFunc(updateGoodsWH1))).Methods("PUT")
	r.Handle("/wh1/{id}", authenticate(http.HandlerFunc(deleteGoodsWH1))).Methods("DELETE")

	r.Handle("/wh2", authenticate(http.HandlerFunc(getGoodsWH2))).Methods("GET")
	r.Handle("/wh2", authenticate(http.HandlerFunc(addGoodsWH2))).Methods("POST")
	r.Handle("/wh2/{id}", authenticate(http.HandlerFunc(updateGoodsWH2))).Methods("PUT")
	r.Handle("/wh2/{id}", authenticate(http.HandlerFunc(deleteGoodsWH2))).Methods("DELETE")

	r.Handle("/goodsw1", authenticate(http.HandlerFunc(getGoodsw1))).Methods("GET")
	r.Handle("/goodsw2", authenticate(http.HandlerFunc(getGoodsw2))).Methods("GET")
	r.Handle("/wadd/{warehouseId}", authenticate(http.HandlerFunc(addBatchToWarehouse))).Methods("POST")

	r.Handle("/wh/{warehouseId}", authenticate(http.HandlerFunc(getGoodsWH))).Methods("GET")

	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	origins := handlers.AllowedOrigins([]string{"*"})

	fmt.Println("Сервер запущен на :8000")
	log.Fatal(http.ListenAndServe(":8000", handlers.CORS(headers, methods, origins)(r)))
}

func getGoods(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, priority FROM goods")
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка выполнения запроса: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var goods []struct {
		ID       int     `json:"id"`
		Name     string  `json:"name"`
		Priority float64 `json:"priority"`
	}

	for rows.Next() {
		var g struct {
			ID       int     `json:"id"`
			Name     string  `json:"name"`
			Priority float64 `json:"priority"`
		}
		err := rows.Scan(&g.ID, &g.Name, &g.Priority)
		if err != nil {
			http.Error(w, fmt.Sprintf("Ошибка чтения строки: %v", err), http.StatusInternalServerError)
			return
		}
		goods = append(goods, g)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Ошибка итерации по строкам: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(goods)
}

func getTopGoods(w http.ResponseWriter, r *http.Request) {
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	if start == "" || end == "" {
		http.Error(w, "Start and end parameters are required", http.StatusBadRequest)
		return
	}
	log.Println("Received start date:", start)
	log.Println("Received end date:", end)
	query := `
        SELECT g.name, SUM(s.good_count) AS total_sold 
        FROM sales s 
        JOIN goods g ON s.good_id = g.id 
        WHERE s.create_date BETWEEN $1::DATE AND $2::DATE 
        GROUP BY g.name 
        ORDER BY total_sold DESC 
        LIMIT 5`
	rows, err := db.Query(query, start, end)
	if err != nil {
		log.Println("Error querying top goods:", err)
		http.Error(w, "Could not fetch top goods", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var topGoods []struct {
		Name      string `json:"name"`
		TotalSold int    `json:"total_sold"`
	}

	for rows.Next() {
		var good struct {
			Name      string `json:"name"`
			TotalSold int    `json:"total_sold"`
		}
		if err := rows.Scan(&good.Name, &good.TotalSold); err != nil {
			log.Println("Error scanning row:", err)
			http.Error(w, "Could not scan row", http.StatusInternalServerError)
			return
		}
		topGoods = append(topGoods, good)
	}
	log.Println("Fetched top goods:", topGoods)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topGoods)
}

func getDemandChange(w http.ResponseWriter, r *http.Request) {
	goodID := r.URL.Query().Get("good_id")
	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")

	query := `
    SELECT s.create_date::date AS date, SUM(s.good_count) AS total_sold
    FROM sales s
    WHERE s.good_id = $1 AND s.create_date BETWEEN $2 AND $3
    GROUP BY s.create_date::date
    ORDER BY s.create_date::date
    `
	rows, err := db.Query(query, goodID, startDate, endDate)
	if err != nil {
		http.Error(w, "Could not fetch demand change", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var demandData []struct {
		Date      string `json:"date"`
		TotalSold int    `json:"total_sold"`
	}

	for rows.Next() {
		var demand struct {
			Date      string `json:"date"`
			TotalSold int    `json:"total_sold"`
		}
		if err := rows.Scan(&demand.Date, &demand.TotalSold); err != nil {
			http.Error(w, "Could not scan row", http.StatusInternalServerError)
			return
		}
		demandData = append(demandData, demand)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(demandData)
}

func getWarehouseCounts(w http.ResponseWriter, r *http.Request) {
	goodID := r.URL.Query().Get("good_id")
	if goodID == "" {
		http.Error(w, "good_id parameter is required", http.StatusBadRequest)
		return
	}

	query := `
        SELECT 
            COALESCE((SELECT good_count FROM warehouse1 WHERE good_id = $1), 0) AS warehouse1_count,
            COALESCE((SELECT good_count FROM warehouse2 WHERE good_id = $1), 0) AS warehouse2_count
    `
	row := db.QueryRow(query, goodID)

	var warehouse1Count, warehouse2Count int64
	if err := row.Scan(&warehouse1Count, &warehouse2Count); err != nil {
		http.Error(w, "Could not fetch warehouse data", http.StatusInternalServerError)
		return
	}

	response := struct {
		Warehouse1Count int64 `json:"warehouse1_count"`
		Warehouse2Count int64 `json:"warehouse2_count"`
	}{
		Warehouse1Count: warehouse1Count,
		Warehouse2Count: warehouse2Count,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func nullInt64ToPtr(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	return &n.Int64
}

func getSalesCounts(w http.ResponseWriter, r *http.Request) {
	goodID := r.URL.Query().Get("good_id")
	var quantity int
	var priority float64

	err := db.QueryRow(`
        SELECT COALESCE(SUM(s.good_count), 0) AS total_quantity, COALESCE(g.priority, 0) AS priority 
        FROM sales s 
        RIGHT JOIN goods g ON s.good_id = g.id 
        WHERE g.id = $1 
        GROUP BY g.priority
    `, goodID).Scan(&quantity, &priority)

	if err != nil {
		if err == sql.ErrNoRows {
			quantity = 0
			priority = 0
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	response := map[string]interface{}{
		"quantity": quantity,
		"priority": priority,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func forecastDemand(w http.ResponseWriter, r *http.Request) {
	goodID := r.URL.Query().Get("good_id")
	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")

	if goodID == "" || startDate == "" || endDate == "" {
		http.Error(w, "good_id, start_date, and end_date parameters are required", http.StatusBadRequest)
		return
	}

	var day2Count int
	var diff float64
	var forecast float64

	err := db.QueryRow(`CALL forecast_demand2($1::DATE, $2::DATE, $3::INT, $4::DOUBLE PRECISION, $5::INT, $6::DOUBLE PRECISION)`,
		startDate, endDate, goodID, &forecast, &day2Count, &diff).Scan(&forecast, &day2Count, &diff)

	if err != nil {
		http.Error(w, "Could not fetch forecast demand", http.StatusInternalServerError)
		log.Printf("Error fetching forecast result: %v", err)
		return
	}

	log.Printf("day2Count: %d, diff: %f", day2Count, diff)

	forecasts := make([]float64, 7)
	for i := 0; i < 7; i++ {
		forecasts[i] = float64(day2Count) + (diff * float64(i+1))
	}

	response := struct {
		Forecast []float64 `json:"forecast"`
	}{
		Forecast: forecasts,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

type GoodForTransfer struct {
	GoodID         int     `json:"good_id"`
	GoodName       string  `json:"good_name"`
	NeedToTransfer string  `json:"need_to_transfer"`
	Priority       float64 `json:"priority"`
}

func getGoodsForTransfer(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT good_id, good_name, need_to_transfer, priority FROM get_goods_for_transfer()") // Изменено на good_id
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка выполнения запроса: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var goodsForTransfer []GoodForTransfer
	for rows.Next() {
		var g GoodForTransfer
		if err := rows.Scan(&g.GoodID, &g.GoodName, &g.NeedToTransfer, &g.Priority); err != nil {
			http.Error(w, fmt.Sprintf("Ошибка чтения строки: %v", err), http.StatusInternalServerError)
			return
		}
		goodsForTransfer = append(goodsForTransfer, g)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Ошибка итерации по строкам: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(goodsForTransfer)
}

type Good struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	Priority float64 `json:"priority"`
}

func getGoods1(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, priority FROM goods ORDER BY id ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var goods []Good
	for rows.Next() {
		var good Good
		if err := rows.Scan(&good.ID, &good.Name, &good.Priority); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		goods = append(goods, good)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(goods)
}

func addGood(w http.ResponseWriter, r *http.Request) {
	var good Good
	if err := json.NewDecoder(r.Body).Decode(&good); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := db.QueryRow("INSERT INTO goods (name, priority) VALUES ($1, $2) RETURNING id", good.Name, good.Priority).Scan(&good.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(good)
}

func updateGood(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var good Good
	if err := json.NewDecoder(r.Body).Decode(&good); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE goods SET name=$1, priority=$2 WHERE id=$3", good.Name, good.Priority, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func deleteGood(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, err := db.Exec("DELETE FROM goods WHERE id=$1", id)
	if err != nil {
		if err.Error() == "pq: Невозможно удалить товар, так как он находится на складе 2" {
			http.Error(w, "Невозможно удалить товар, так как он находится на складе 2", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type TransferRequest struct {
	GoodID         int `json:"good_id"`
	TransferAmount int `json:"amount"`
}

func transferGoods(w http.ResponseWriter, r *http.Request) {
	var transfer TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&transfer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Received transfer request: %+v\n", transfer)
	if transfer.GoodID == 0 || transfer.TransferAmount == 0 {
		http.Error(w, "Неверные данные: good_id или amount не указаны", http.StatusBadRequest)
		return
	}

	var salesCount int
	err := db.QueryRow("SELECT SUM(good_count) FROM sales WHERE good_id=$1", transfer.GoodID).Scan(&salesCount)
	if err != nil {
		log.Printf("Error querying sales: %v\n", err)
		http.Error(w, "Ошибка при запросе количества товара в заявках", http.StatusInternalServerError)
		return
	}
	log.Printf("Sales count for good_id %d: %d\n", transfer.GoodID, salesCount)

	var availableInWarehouse1 int
	err = db.QueryRow("SELECT COALESCE(good_count, 0) FROM warehouse1 WHERE good_id=$1", transfer.GoodID).Scan(&availableInWarehouse1)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error querying warehouse1: %v\n", err)
		http.Error(w, "Ошибка при запросе товара на складе 1", http.StatusInternalServerError)
		return
	} else if err == sql.ErrNoRows {
		availableInWarehouse1 = 0
	}

	log.Printf("Available in warehouse1 for good_id %d: %d\n", transfer.GoodID, availableInWarehouse1)

	var availableInWarehouse2 int
	err = db.QueryRow("SELECT COALESCE(good_count, 0) FROM warehouse2 WHERE good_id=$1", transfer.GoodID).Scan(&availableInWarehouse2)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error querying warehouse2: %v\n", err)
		http.Error(w, "Ошибка при запросе товара на складе 2", http.StatusInternalServerError)
		return
	} else if err == sql.ErrNoRows {
		availableInWarehouse2 = 0
	}
	log.Printf("Available in warehouse2 for good_id %d: %d\n", transfer.GoodID, availableInWarehouse2)

	if availableInWarehouse1+availableInWarehouse2 < salesCount {
		log.Printf("Not enough goods for sales: available (%d+%d) < sales (%d)\n", availableInWarehouse1, availableInWarehouse2, salesCount)
		http.Error(w, "Невозможно выполнить заявки по товару — недостаточно товара на складах", http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Ошибка при создании транзакции", http.StatusInternalServerError)
		return
	}

	if availableInWarehouse1 >= salesCount {
		_, err = tx.Exec("UPDATE warehouse1 SET good_count = good_count - $1 WHERE good_id = $2", salesCount, transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error updating warehouse1: %v\n", err)
			http.Error(w, "Ошибка при списании товара со склада 1", http.StatusInternalServerError)
			return
		}
		_, err = tx.Exec("DELETE FROM sales WHERE good_id = $1", transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error deleting sales: %v\n", err)
			http.Error(w, "Ошибка при удалении заявок", http.StatusInternalServerError)
			return
		}
	} else {
		_, err = tx.Exec("UPDATE warehouse1 SET good_count = 0 WHERE good_id = $1", transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error updating warehouse1 to zero: %v\n", err)
			http.Error(w, "Ошибка при списании товара со склада 1", http.StatusInternalServerError)
			return
		}
		remainingSalesCount := salesCount - availableInWarehouse1
		_, err = tx.Exec("UPDATE warehouse2 SET good_count = good_count - $1 WHERE good_id = $2", remainingSalesCount, transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error updating warehouse2: %v\n", err)
			http.Error(w, "Ошибка при списании товара со склада 2", http.StatusInternalServerError)
			return
		}

		_, err = tx.Exec("DELETE FROM sales WHERE good_id = $1", transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error deleting sales after warehouse2 update: %v\n", err)
			http.Error(w, "Ошибка при удалении заявок", http.StatusInternalServerError)
			return
		}
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("Error committing transaction: %v\n", err)
		http.Error(w, "Ошибка при фиксации транзакции", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Товар успешно списан и заявки выполнены"))
}

type Sale struct {
	ID         int    `json:"id"`
	GoodID     int    `json:"good_id"`
	GoodCount  int    `json:"good_count"`
	CreateDate string `json:"create_date"`
	GoodName   string `json:"good_name"`
}

func getSales(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT s.id, s.good_id, g.name AS good_name, s.good_count, s.create_date 
		FROM sales s 
		JOIN goods g ON s.good_id = g.id 
		ORDER BY s.id ASC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var sales []Sale
	for rows.Next() {
		var sale Sale
		if err := rows.Scan(&sale.ID, &sale.GoodID, &sale.GoodName, &sale.GoodCount, &sale.CreateDate); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sales = append(sales, sale)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sales)
}

func addSale(w http.ResponseWriter, r *http.Request) {
	var sale Sale
	if err := json.NewDecoder(r.Body).Decode(&sale); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := db.QueryRow("INSERT INTO sales (good_id, good_count, create_date) VALUES ($1, $2, $3) RETURNING id", sale.GoodID, sale.GoodCount, sale.CreateDate).Scan(&sale.ID)
	if err != nil {
		if err.Error() == "Недостаточно товара на складах для добавления заявки." {
			http.Error(w, "Недостаточно товара на складах для добавления заявки.", http.StatusConflict)
			return
		} else if err.Error() == "Количество товара должно быть больше или равно 1." {
			http.Error(w, "Количество товара должно быть больше или равно 1.", http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(sale)
}

func updateSale(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var sale Sale
	if err := json.NewDecoder(r.Body).Decode(&sale); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE sales SET good_id=$1, good_count=$2, create_date=$3 WHERE id=$4", sale.GoodID, sale.GoodCount, sale.CreateDate, id)
	if err != nil {
		if err.Error() == "Недостаточно товара на складах для выполнения заявки." {
			http.Error(w, "Недостаточно товара на складах для выполнения заявки.", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func deleteSale(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, err := db.Exec("DELETE FROM sales WHERE id=$1", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type GoodWH1 struct {
	ID        int    `json:"id"`
	GoodID    int    `json:"good_id"`
	GoodName  string `json:"good_name"`
	GoodCount int    `json:"good_count"`
}

func getGoodsWH1(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
	SELECT w.id, w.good_id, g.name AS good_name, w.good_count
	FROM warehouse1 w
	JOIN goods g ON w.good_id = g.id
	ORDER BY w.id ASC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var goodsWH1 []GoodWH1
	for rows.Next() {
		var good GoodWH1
		if err := rows.Scan(&good.ID, &good.GoodID, &good.GoodName, &good.GoodCount); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		goodsWH1 = append(goodsWH1, good)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(goodsWH1)
}

func addGoodsWH1(w http.ResponseWriter, r *http.Request) {
	var goodwh1 GoodWH1
	if err := json.NewDecoder(r.Body).Decode(&goodwh1); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := db.QueryRow("INSERT INTO warehouse1 (good_id, good_count) VALUES ($1, $2) RETURNING id", goodwh1.GoodID, goodwh1.GoodCount).Scan(&goodwh1.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(goodwh1)
}

func updateGoodsWH1(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var goodwh1 GoodWH1
	if err := json.NewDecoder(r.Body).Decode(&goodwh1); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE warehouse1 SET good_id=$1, good_count=$2 WHERE id=$3", goodwh1.GoodID, goodwh1.GoodCount, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func deleteGoodsWH1(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, err := db.Exec("DELETE FROM warehouse1 WHERE id=$1", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type GoodWH2 struct {
	ID        int    `json:"id"`
	GoodID    int    `json:"good_id"`
	GoodName  string `json:"good_name"`
	GoodCount int    `json:"good_count"`
}

func getGoodsWH2(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
	SELECT w.id, w.good_id, g.name AS good_name, w.good_count
	FROM warehouse2 w
	JOIN goods g ON w.good_id=g.id
	ORDER BY w.id ASC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var goodswh2 []GoodWH2
	for rows.Next() {
		var good GoodWH2
		if err := rows.Scan(&good.ID, &good.GoodID, &good.GoodName, &good.GoodCount); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		goodswh2 = append(goodswh2, good)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&goodswh2)
}

func addGoodsWH2(w http.ResponseWriter, r *http.Request) {
	var good GoodWH2
	if err := json.NewDecoder(r.Body).Decode(&good); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := db.QueryRow("INSERT INTO warehouse2 (good_id, good_count) VALUES ($1, $2) RETURNING id", good.GoodID, good.GoodCount).Scan(&good.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(&good)
}

func updateGoodsWH2(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var good GoodWH2
	if err := json.NewDecoder(r.Body).Decode(&good); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := db.Exec("UPDATE warehouse2 SET good_id=$1, good_count=$2 WHERE id=$3", good.GoodID, good.GoodCount, id)
	if err != nil {
		if err.Error() == "Нельзя уменьшать количество товара на складе 2, пока он есть на складе 1" {
			http.Error(w, "Нельзя уменьшать количество товара на складе 2, пока он есть на складе 1", http.StatusInternalServerError)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func deleteGoodsWH2(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, err := db.Exec("DELETE FROM warehouse2 WHERE id=$1", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getGoodsw1(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
	SELECT g.id, g.name
	FROM goods g
	lEFT JOIN warehouse1 w ON g.id=w.good_id
	WHERE w.good_id IS NULL
	ORDER BY g.name ASC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var goods []GoodWH1
	for rows.Next() {
		var good GoodWH1
		if err := rows.Scan(&good.ID, &good.GoodName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		goods = append(goods, good)
	}

	w.Header().Set("Content-Type", "json/application")
	json.NewEncoder(w).Encode(&goods)
}

func getGoodsw2(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
	SELECT g.id, g.name 
	FROM goods g
	lEFT JOIN warehouse2 w ON g.id=w.good_id
	WHERE w.good_id IS NULL
	ORDER BY g.name ASC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var goods []GoodWH2
	for rows.Next() {
		var good GoodWH2
		if err := rows.Scan(&good.ID, &good.GoodName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		goods = append(goods, good)
	}

	w.Header().Set("Content-Type", "json/application")
	json.NewEncoder(w).Encode(&goods)
}

type GoodWH struct {
	ID        int    `json:"id"`
	GoodID    int    `json:"good_id"`
	GoodName  string `json:"good_name"`
	GoodCount int    `json:"good_count"`
}

func addBatchToWarehouse(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	warehouseID := vars["warehouseId"]

	if warehouseID != "1" && warehouseID != "2" {
		http.Error(w, "Invalid warehouse ID", http.StatusBadRequest)
		return
	}

	var newGoods []map[string]interface{}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&newGoods); err != nil {
		log.Printf("Failed to decode JSON body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var convertedGoods []GoodWH
	for _, good := range newGoods {
		goodID, ok := good["good_id"].(string)
		if !ok {
			http.Error(w, "Invalid good_id format", http.StatusBadRequest)
			return
		}

		goodIDInt, err := strconv.Atoi(goodID)
		if err != nil {
			http.Error(w, "Invalid good_id value", http.StatusBadRequest)
			return
		}

		goodCountFloat, ok := good["good_count"].(float64)
		if !ok {
			http.Error(w, "Invalid good_count format", http.StatusBadRequest)
			return
		}
		goodCount := int(goodCountFloat)

		convertedGoods = append(convertedGoods, GoodWH{
			GoodID:    goodIDInt,
			GoodCount: goodCount,
		})
	}

	var query string
	if warehouseID == "1" {
		query = `
            UPDATE warehouse1 
            SET good_count = good_count + $2 
            WHERE good_id = $1`
	} else if warehouseID == "2" {
		query = `
            UPDATE warehouse2 
            SET good_count = good_count + $2 
            WHERE good_id = $1`
	}

	for _, good := range convertedGoods {
		_, err := db.Exec(query, good.GoodID, good.GoodCount)
		if err != nil {
			log.Printf("Failed to execute query for good_id: %d, error: %v\n", good.GoodID, err)
			http.Error(w, "Failed to add/update goods", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
}

func getGoodsWH(w http.ResponseWriter, r *http.Request) {
	fmt.Println("GET request received on /wh/{warehouseId}")
	vars := mux.Vars(r)
	warehouseID := vars["warehouseId"]
	fmt.Printf("Warehouse ID: %s\n", warehouseID)

	if warehouseID != "1" && warehouseID != "2" {
		http.Error(w, "Invalid warehouse ID", http.StatusBadRequest)
		return
	}

	var query string

	switch warehouseID {
	case "1":
		query = `
			SELECT w.id, w.good_id, g.name AS good_name, w.good_count
			FROM warehouse1 w
			JOIN goods g ON w.good_id = g.id
			ORDER BY w.id ASC`
	case "2":
		query = `
			SELECT w.id, w.good_id, g.name AS good_name, w.good_count
			FROM warehouse2 w
			JOIN goods g ON w.good_id = g.id
			ORDER BY w.id ASC`
	default:
		http.Error(w, "Invalid warehouse ID", http.StatusBadRequest)
		return
	}

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var goods []GoodWH
	for rows.Next() {
		var good GoodWH
		if err := rows.Scan(&good.ID, &good.GoodID, &good.GoodName, &good.GoodCount); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		goods = append(goods, good)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(goods)
}
