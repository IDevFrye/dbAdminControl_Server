package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtKey = []byte("your_secret_key") // Секретный ключ для JWT

// Структура для JWT claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// Структура для входных данных
type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Подключение к базе данных
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

// Проверка логина и пароля
func login(w http.ResponseWriter, r *http.Request) {
	var input LoginInput
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Проверка пользователя в базе данных
	var storedHash string
	var role string
	err = db.QueryRow("SELECT password_hash, role FROM users WHERE username = $1", input.Username).Scan(&storedHash, &role)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Сравнение паролей
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(input.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Создание JWT токена
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

	// Подготовка ответа
	response := struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}{
		Token: tokenString,
		Role:  role,
	}

	// Отправка JSON-ответа
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Middleware для проверки JWT
func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Проверка заголовка Authorization
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Удаление 'Bearer ' из строки токена
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

	// Авторизация
	r.HandleFunc("/login", login).Methods("POST")

	// Пример защищенного маршрута
	r.Handle("/goods", authenticate(http.HandlerFunc(getGoods))).Methods("GET")
	r.Handle("/top_goods", authenticate(http.HandlerFunc(getTopGoods))).Methods("GET")
	r.Handle("/demand_change", authenticate(http.HandlerFunc(getDemandChange))).Methods("GET")

	// Новый маршрут для прогнозирования спроса
	r.Handle("/forecast_demand", authenticate(http.HandlerFunc(forecastDemand))).Methods("GET")
	r.Handle("/goods-for-transfer", authenticate(http.HandlerFunc(getGoodsForTransfer))).Methods("GET")

	// Новые маршруты для получения данных о складах и продажах
	r.Handle("/warehouse_counts", authenticate(http.HandlerFunc(getWarehouseCounts))).Methods("GET")
	r.Handle("/sales_counts", authenticate(http.HandlerFunc(getSalesCounts))).Methods("GET")
	r.Handle("/transfer-goods", authenticate(http.HandlerFunc(transferGoods))).Methods("POST")

	r.Handle("/goods1", authenticate(http.HandlerFunc(getGoods1))).Methods("GET")         // Получить все товары
	r.Handle("/goods", authenticate(http.HandlerFunc(addGood))).Methods("POST")           // Добавить новый товар
	r.Handle("/goods/{id}", authenticate(http.HandlerFunc(updateGood))).Methods("PUT")    // Обновить товар по ID
	r.Handle("/goods/{id}", authenticate(http.HandlerFunc(deleteGood))).Methods("DELETE") // Удалить товар по ID

	// Заявки
	r.Handle("/sales", authenticate(http.HandlerFunc(getSales))).Methods("GET")           // Получить все заявки
	r.Handle("/sales", authenticate(http.HandlerFunc(addSale))).Methods("POST")           // Добавить новую заявку
	r.Handle("/sales/{id}", authenticate(http.HandlerFunc(updateSale))).Methods("PUT")    // Обновить заявку по ID
	r.Handle("/sales/{id}", authenticate(http.HandlerFunc(deleteSale))).Methods("DELETE") // Удалить заявку по ID

	// Настройка CORS
	// Настройка CORS
	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	origins := handlers.AllowedOrigins([]string{"*"})

	fmt.Println("Сервер запущен на :8000")
	log.Fatal(http.ListenAndServe(":8000", handlers.CORS(headers, methods, origins)(r)))
}

// Обработчик для получения товаров
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

	// Проверка на ошибки при итерации по строкам
	if err := rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Ошибка итерации по строкам: %v", err), http.StatusInternalServerError)
		return
	}

	// Отправляем JSON-ответ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(goods)
}

func getTopGoods(w http.ResponseWriter, r *http.Request) {
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	// Проверка на пустые параметры
	if start == "" || end == "" {
		http.Error(w, "Start and end parameters are required", http.StatusBadRequest)
		return
	}

	// Логирование перед запросом для отладки
	log.Println("Received start date:", start)
	log.Println("Received end date:", end)

	// Приведение строковых параметров к типу DATE в запросе
	query := `
        SELECT g.name, SUM(s.good_count) AS total_sold 
        FROM sales s 
        JOIN goods g ON s.good_id = g.id 
        WHERE s.create_date BETWEEN $1::DATE AND $2::DATE 
        GROUP BY g.name 
        ORDER BY total_sold DESC 
        LIMIT 5`

	// Выполнение запроса с параметрами
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

	// Сканирование данных из результата запроса
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
	// Отправка ответа в формате JSON
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

// Обработчик для получения количества товаров на складах
// Обработчик для получения количества товаров на складах
func getWarehouseCounts(w http.ResponseWriter, r *http.Request) {
	goodID := r.URL.Query().Get("good_id")
	if goodID == "" {
		http.Error(w, "good_id parameter is required", http.StatusBadRequest)
		return
	}

	// Запрос для получения количества товара из обеих таблиц складов
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

	// Создание структуры ответа
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

// Функция для преобразования sql.NullInt64 в указатель на int64
func nullInt64ToPtr(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	return &n.Int64
}

func getSalesCounts(w http.ResponseWriter, r *http.Request) {
	// Получаем good_id из запроса
	goodID := r.URL.Query().Get("good_id")
	var quantity int
	var priority float64

	// Подключение к базе данных и выполнение запроса
	err := db.QueryRow(`
        SELECT COALESCE(SUM(s.good_count), 0) AS total_quantity, COALESCE(g.priority, 0) AS priority 
        FROM sales s 
        RIGHT JOIN goods g ON s.good_id = g.id 
        WHERE g.id = $1 
        GROUP BY g.priority
    `, goodID).Scan(&quantity, &priority)

	if err != nil {
		// Проверяем, не является ли ошибка ошибкой "no rows"
		if err == sql.ErrNoRows {
			quantity = 0
			priority = 0
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Возвращаем данные в формате JSON
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
	var forecast float64 // Можем игнорировать это значение, но оно необходимо для вызова процедуры

	// Используем QueryRow для получения значений из OUT параметров хранимой процедуры
	err := db.QueryRow(`CALL forecast_demand2($1::DATE, $2::DATE, $3::INT, $4::DOUBLE PRECISION, $5::INT, $6::DOUBLE PRECISION)`,
		startDate, endDate, goodID, &forecast, &day2Count, &diff).Scan(&forecast, &day2Count, &diff)

	if err != nil {
		http.Error(w, "Could not fetch forecast demand", http.StatusInternalServerError)
		log.Printf("Error fetching forecast result: %v", err)
		return
	}

	// Логирование возвращаемых значений
	log.Printf("day2Count: %d, diff: %f", day2Count, diff)

	// Расчет прогнозов на 7 дней
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
	GoodID         int     `json:"good_id"` // Добавлено поле ID
	GoodName       string  `json:"good_name"`
	NeedToTransfer string  `json:"need_to_transfer"`
	Priority       float64 `json:"priority"`
}

func getGoodsForTransfer(w http.ResponseWriter, r *http.Request) {
	// Вызов хранимой функции или SQL-запроса, который должен возвращать ID товара
	rows, err := db.Query("SELECT good_id, good_name, need_to_transfer, priority FROM get_goods_for_transfer()") // Изменено на good_id
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка выполнения запроса: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Массив для хранения результатов
	var goodsForTransfer []GoodForTransfer

	// Обрабатываем строки результата
	for rows.Next() {
		var g GoodForTransfer
		// Сканируем также поле ID товара
		if err := rows.Scan(&g.GoodID, &g.GoodName, &g.NeedToTransfer, &g.Priority); err != nil {
			http.Error(w, fmt.Sprintf("Ошибка чтения строки: %v", err), http.StatusInternalServerError)
			return
		}
		goodsForTransfer = append(goodsForTransfer, g)
	}

	// Проверяем наличие ошибок при итерации по строкам
	if err := rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Ошибка итерации по строкам: %v", err), http.StatusInternalServerError)
		return
	}

	// Отправляем JSON-ответ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(goodsForTransfer)
}

type Good struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	Priority float64 `json:"priority"`
}

// Получить все товары
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

// Добавить новый товар
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

// Обновить товар
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

// Удалить товар
// Удалить товар
func deleteGood(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, err := db.Exec("DELETE FROM goods WHERE id=$1", id)
	if err != nil {
		// Если ошибка удаления связана с триггером, возвращаем ошибку с сообщением
		if err.Error() == "pq: Невозможно удалить товар, так как он находится на складе 2" {
			http.Error(w, "Невозможно удалить товар, так как он находится на складе 2", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// API для перевода товара со второго склада на первый
type TransferRequest struct {
	GoodID         int `json:"good_id"` // ID товара
	TransferAmount int `json:"amount"`  // Количество для перевода
}

// API для обработки списания товара с учетом заявок
func transferGoods(w http.ResponseWriter, r *http.Request) {
	var transfer TransferRequest

	// Попытка декодирования JSON
	if err := json.NewDecoder(r.Body).Decode(&transfer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Логирование полученных данных
	log.Printf("Received transfer request: %+v\n", transfer)

	// Проверяем, что получили нужные поля
	if transfer.GoodID == 0 || transfer.TransferAmount == 0 {
		http.Error(w, "Неверные данные: good_id или amount не указаны", http.StatusBadRequest)
		return
	}

	// Определяем количество товара в заявках (sales)
	var salesCount int
	err := db.QueryRow("SELECT SUM(good_count) FROM sales WHERE good_id=$1", transfer.GoodID).Scan(&salesCount)
	if err != nil {
		log.Printf("Error querying sales: %v\n", err)
		http.Error(w, "Ошибка при запросе количества товара в заявках", http.StatusInternalServerError)
		return
	}

	// Логирование количества товара в заявках
	log.Printf("Sales count for good_id %d: %d\n", transfer.GoodID, salesCount)

	// Определяем количество товара на складе 1
	var availableInWarehouse1 int
	err = db.QueryRow("SELECT good_count FROM warehouse1 WHERE good_id=$1", transfer.GoodID).Scan(&availableInWarehouse1)
	if err != nil {
		log.Printf("Error querying warehouse1: %v\n", err)
		http.Error(w, "Ошибка при запросе товара на складе 1", http.StatusInternalServerError)
		return
	}

	// Логирование количества товара на складе 1
	log.Printf("Available in warehouse1 for good_id %d: %d\n", transfer.GoodID, availableInWarehouse1)

	// Определяем количество товара на складе 2
	var availableInWarehouse2 int
	err = db.QueryRow("SELECT good_count FROM warehouse2 WHERE good_id=$1", transfer.GoodID).Scan(&availableInWarehouse2)
	if err != nil {
		log.Printf("Error querying warehouse2: %v\n", err)
		http.Error(w, "Ошибка при запросе товара на складе 2", http.StatusInternalServerError)
		return
	}

	// Логирование количества товара на складе 2
	log.Printf("Available in warehouse2 for good_id %d: %d\n", transfer.GoodID, availableInWarehouse2)

	// Проверка на возможность выполнения всех заявок
	if availableInWarehouse1+availableInWarehouse2 < salesCount {
		log.Printf("Not enough goods for sales: available (%d+%d) < sales (%d)\n", availableInWarehouse1, availableInWarehouse2, salesCount)
		http.Error(w, "Невозможно выполнить заявки по товару — недостаточно товара на складах", http.StatusBadRequest)
		return
	}

	// Открываем транзакцию для атомарных операций
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Ошибка при создании транзакции", http.StatusInternalServerError)
		return
	}

	// Логика списания товара
	if availableInWarehouse1 >= salesCount {
		// Если товара на складе 1 достаточно для выполнения всех заявок
		_, err = tx.Exec("UPDATE warehouse1 SET good_count = good_count - $1 WHERE good_id = $2", salesCount, transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error updating warehouse1: %v\n", err)
			http.Error(w, "Ошибка при списании товара со склада 1", http.StatusInternalServerError)
			return
		}
		// Удаляем выполненные заявки
		_, err = tx.Exec("DELETE FROM sales WHERE good_id = $1", transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error deleting sales: %v\n", err)
			http.Error(w, "Ошибка при удалении заявок", http.StatusInternalServerError)
			return
		}
	} else {
		// Если товара на складе 1 недостаточно, списываем все с первого склада
		_, err = tx.Exec("UPDATE warehouse1 SET good_count = 0 WHERE good_id = $1", transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error updating warehouse1 to zero: %v\n", err)
			http.Error(w, "Ошибка при списании товара со склада 1", http.StatusInternalServerError)
			return
		}

		// Списываем недостающее количество с второго склада
		remainingSalesCount := salesCount - availableInWarehouse1
		_, err = tx.Exec("UPDATE warehouse2 SET good_count = good_count - $1 WHERE good_id = $2", remainingSalesCount, transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error updating warehouse2: %v\n", err)
			http.Error(w, "Ошибка при списании товара со склада 2", http.StatusInternalServerError)
			return
		}

		// Удаляем выполненные заявки
		_, err = tx.Exec("DELETE FROM sales WHERE good_id = $1", transfer.GoodID)
		if err != nil {
			tx.Rollback()
			log.Printf("Error deleting sales after warehouse2 update: %v\n", err)
			http.Error(w, "Ошибка при удалении заявок", http.StatusInternalServerError)
			return
		}
	}

	// Фиксируем транзакцию
	err = tx.Commit()
	if err != nil {
		log.Printf("Error committing transaction: %v\n", err)
		http.Error(w, "Ошибка при фиксации транзакции", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Товар успешно списан и заявки выполнены"))
}

// Структура для заявки
type Sale struct {
	ID         int    `json:"id"`
	GoodID     int    `json:"good_id"`
	GoodCount  int    `json:"good_count"`
	CreateDate string `json:"create_date"`
	GoodName   string `json:"good_name"` // Новое поле для названия товара
}

// Получить все заявки
// Получить заявки
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

// Добавить новую заявку
// Добавить новую заявку
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

// Обновить заявку
func updateSale(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var sale Sale
	if err := json.NewDecoder(r.Body).Decode(&sale); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE sales SET good_id=$1, good_count=$2, create_date=$3 WHERE id=$4", sale.GoodID, sale.GoodCount, sale.CreateDate, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Удалить заявку
func deleteSale(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_, err := db.Exec("DELETE FROM sales WHERE id=$1", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
