module github.com/antoineross/supabase-go

go 1.21.1

toolchain go1.22.1

require (
	github.com/joho/godotenv v1.5.1
	github.com/supabase-community/auth-go v1.3.2
	github.com/supabase-community/functions-go v0.1.0
	github.com/supabase-community/postgrest-go v0.0.11
	github.com/supabase-community/storage-go v0.7.0
	github.com/supabase-community/supabase-go v0.0.4
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/supabase-community/gotrue-go v1.2.1 // indirect
	github.com/tomnomnom/linkheader v0.0.0-20180905144013-02ca5825eb80 // indirect
)

replace github.com/supabase-community/postgrest-go => github.com/roja/postgrest-go v0.0.11

replace github.com/supabase-community/functions-go => github.com/roja/functions-go v0.0.2
