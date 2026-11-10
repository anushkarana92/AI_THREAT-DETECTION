#include <stdio.h>
#include <string.h>

#define MAX_THREATS 100

/* =====================================
   THREAT STRUCTURE
   ===================================== */

typedef struct {
    int id;
    char sourceIP[40];
    char threatType[40];
    int failedLogins;
    int unusualTraffic;
    int riskScore;
} Threat;


/* =====================================
   QUEUE IMPLEMENTATION
   ===================================== */

typedef struct {
    Threat items[MAX_THREATS];
    int front;
    int rear;
    int size;
} Queue;

void initializeQueue(Queue *q) {
    q->front = 0;
    q->rear = -1;
    q->size = 0;
}

int isQueueEmpty(Queue *q) {
    return q->size == 0;
}

int isQueueFull(Queue *q) {
    return q->size == MAX_THREATS;
}

void enqueue(Queue *q, Threat t) {
    if (isQueueFull(q)) {
        printf("Queue is full!\n");
        return;
    }

    q->rear = (q->rear + 1) % MAX_THREATS;
    q->items[q->rear] = t;
    q->size++;

    printf("Threat %d added to Queue.\n", t.id);
}

Threat dequeue(Queue *q) {
    Threat empty = {0};

    if (isQueueEmpty(q)) {
        printf("Queue is empty!\n");
        return empty;
    }

    Threat t = q->items[q->front];

    q->front = (q->front + 1) % MAX_THREATS;
    q->size--;

    return t;
}

void displayQueue(Queue *q) {
    if (isQueueEmpty(q)) {
        printf("\nQueue is empty.\n");
        return;
    }

    printf("\n========== THREAT QUEUE ==========\n");

    for (int i = 0; i < q->size; i++) {
        int index = (q->front + i) % MAX_THREATS;

        printf("ID: %d | Type: %s | Risk: %d\n",
               q->items[index].id,
               q->items[index].threatType,
               q->items[index].riskScore);
    }
}


/* =====================================
   RISK SCORE CALCULATION
   ===================================== */

int calculateRiskScore(Threat t) {
    int risk = 0;

    // Failed login contribution: maximum 50
    risk += t.failedLogins * 5;

    if (risk > 50) {
        risk = 50;
    }

    // Unusual traffic contribution
    if (t.unusualTraffic == 1) {
        risk += 30;
    }

    // Maximum risk score: 100
    if (risk > 100) {
        risk = 100;
    }

    return risk;
}

char *getRiskLevel(int score) {
    if (score >= 70)
        return "HIGH";
    else if (score >= 40)
        return "MEDIUM";
    else
        return "LOW";
}


/* =====================================
   MAX HEAP IMPLEMENTATION
   ===================================== */

typedef struct {
    Threat heap[MAX_THREATS];
    int size;
} MaxHeap;

void initializeHeap(MaxHeap *h) {
    h->size = 0;
}

void swapThreat(Threat *a, Threat *b) {
    Threat temp = *a;
    *a = *b;
    *b = temp;
}

// Insert threat into Max Heap
void insertHeap(MaxHeap *h, Threat t) {
    if (h->size >= MAX_THREATS) {
        printf("Heap is full!\n");
        return;
    }

    int i = h->size;
    h->heap[i] = t;
    h->size++;

    // Heapify Up
    while (i > 0) {
        int parent = (i - 1) / 2;

        if (h->heap[parent].riskScore <
            h->heap[i].riskScore) {

            swapThreat(&h->heap[parent],
                       &h->heap[i]);

            i = parent;
        } else {
            break;
        }
    }
}

// Remove highest-risk threat
Threat extractMax(MaxHeap *h) {
    Threat empty = {0};

    if (h->size == 0) {
        printf("Heap is empty!\n");
        return empty;
    }

    Threat highest = h->heap[0];

    h->heap[0] = h->heap[h->size - 1];
    h->size--;

    // Heapify Down
    int i = 0;

    while (1) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        int largest = i;

        if (left < h->size &&
            h->heap[left].riskScore >
            h->heap[largest].riskScore) {
            largest = left;
        }

        if (right < h->size &&
            h->heap[right].riskScore >
            h->heap[largest].riskScore) {
            largest = right;
        }

        if (largest != i) {
            swapThreat(&h->heap[i],
                       &h->heap[largest]);

            i = largest;
        } else {
            break;
        }
    }

    return highest;
}


/* =====================================
   PROCESS QUEUE INTO MAX HEAP
   ===================================== */

void processThreats(Queue *q, MaxHeap *h) {
    while (!isQueueEmpty(q)) {
        Threat t = dequeue(q);
        insertHeap(h, t);
    }

    printf("\nAll queued threats transferred to Max Heap.\n");
}


/* =====================================
   DISPLAY PRIORITIZED THREATS
   ===================================== */

void displayPrioritizedThreats(MaxHeap *h) {
    if (h->size == 0) {
        printf("\nNo threats available.\n");
        return;
    }

    printf("\n======= PRIORITIZED THREATS =======\n");

    while (h->size > 0) {
        Threat t = extractMax(h);

        printf("\nThreat ID: %d", t.id);
        printf("\nSource IP: %s", t.sourceIP);
        printf("\nThreat Type: %s", t.threatType);
        printf("\nRisk Score: %d", t.riskScore);
        printf("\nRisk Level: %s\n",
               getRiskLevel(t.riskScore));
    }
}


/* =====================================
   MAIN FUNCTION - DEMONSTRATION
   ===================================== */

int main() {

    Queue q;
    MaxHeap h;

    initializeQueue(&q);
    initializeHeap(&h);

    printf("====================================\n");
    printf(" AI CYBER THREAT DETECTION - DSA\n");
    printf("====================================\n");

    // Demonstration threat records
    Threat threats[] = {
        {101, "192.168.1.10", "Brute Force", 10, 1, 0},
        {102, "192.168.1.20", "DDoS Attack", 2, 1, 0},
        {103, "192.168.1.30", "Suspicious Login", 5, 0, 0},
        {104, "192.168.1.40", "Malware", 8, 1, 0},
        {105, "192.168.1.50", "Phishing", 1, 0, 0}
    };

    int count = sizeof(threats) / sizeof(threats[0]);

    // Calculate risk and enqueue threats
    for (int i = 0; i < count; i++) {

        threats[i].riskScore =
            calculateRiskScore(threats[i]);

        enqueue(&q, threats[i]);
    }

    // Display incoming threats
    displayQueue(&q);

    // Transfer threats to Max Heap
    processThreats(&q, &h);

    // Display highest-risk threats first
    displayPrioritizedThreats(&h);

    printf("\n====================================\n");
    printf(" DSA PROCESSING COMPLETED\n");
    printf("====================================\n");

    return 0;
}