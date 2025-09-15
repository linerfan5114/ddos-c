# ddos-c-
ddos program with c++

# نصب dependencies
sudo apt-get install libcurl4-openssl-dev libboost-all-dev libssl-dev

# کامپایل
g++ -std=c++17 -O3 -pthread quantum_warfare.cpp -lcurl -lssl -lcrypto -lboost_system -lboost_thread -o quantum_warfare

# اجرا
sudo ./quantum_warfare https://target-domain.com
