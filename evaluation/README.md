# Hiệu chỉnh ngưỡng lexical và semantic

Tập này tạo một quy trình đo lặp lại được thay vì chọn ngưỡng `0.65` hoặc `0.80` theo cảm tính.

```powershell
.\.venv\Scripts\python.exe -m evaluation.evaluate
```

Quy trình thực hiện:

1. `pairs.jsonl` chứa cặp đoạn văn có nhãn `1` (trùng/tương đương) hoặc `0` (không trùng). Các nhóm nội dung của validation và test không giao nhau.
2. Với lexical, script này dùng unigram + bigram + cosine (bộ đối chiếu cũ của web; web hiện dùng so khớp cụm 4 từ, được đo bằng `benchmark_docs.py` bên dưới). Với semantic, script dùng đúng tiền xử lý tiếng Việt, model SBERT và cosine trên embedding chuẩn hóa.
3. Script thử các ngưỡng từ `0.00` đến `1.00`, bước `0.01`, **chỉ trên validation**. Tiêu chí là F1 cao nhất; nếu hòa thì ưu tiên precision rồi ngưỡng cao hơn.
4. Ngưỡng đã chọn được giữ nguyên khi đo test. Test không được dùng để sửa ngưỡng.
5. `retrieval_corpus.jsonl` và `retrieval_queries.jsonl` đo Recall@1, Recall@3, Recall@5. Semantic truy xuất qua đúng `VectorStore`/FAISS của dự án.

Đầu ra nằm trong `evaluation/results/`:

- `REPORT.md`: bảng kết quả dễ đưa vào báo cáo.
- `metrics.json`: số liệu có cấu trúc.
- `pair_predictions.json`: điểm và dự đoán của từng mẫu để xem FP/FN.

Tập hiện tại là **tập khởi đầu có kiểm soát**, dùng để chứng minh quy trình và phát hiện lỗi. Trước khi chốt ngưỡng cho đồ án, cần thay hoặc bổ sung bằng các cặp chunk từ báo cáo thật, do ít nhất hai người gán nhãn và thống nhất các trường hợp bất đồng. Không được báo cáo số liệu của tập nhỏ này như chất lượng cuối cùng của hệ thống.

## Đo ở mức đoạn/tài liệu: `benchmark_docs.py`

```powershell
.\.venv\Scripts\python.exe -m evaluation.benchmark_docs
```

Sinh dữ liệu có đáp án (seed cố định) từ các đoạn tiếng Việt trong `docs/`: chép nguyên văn, chép một nửa, sửa 10% / 30% số từ, đảo thứ tự câu, cùng đoạn cùng lĩnh vực nhưng không chép và đoạn khác lĩnh vực. So bốn thứ: cosine cũ (0,08), cosine + cụm 4 từ (bản trước), và bộ so khớp n-gram (`n` = 3/4/5, số từ nội dung tối thiểu 0/1/2) của `app/services/shingles.py`. Ngưỡng n-gram chọn trên validation, báo cáo trên test; đồng thời đo sai số của con số tổng so với tỷ lệ chép thật, tỷ lệ cặp được báo trên `pairs.jsonl` và tốc độ trên kho 10 000 đoạn. Kết quả: `evaluation/results/BENCHMARK.md` / `.json`.

Giới hạn cần nói rõ khi báo cáo: văn bản "sửa" là xóa/thay từ ngẫu nhiên chứ không phải diễn đạt lại; đoạn nguồn và đoạn kiểm tra đều lấy từ cùng một nhóm tài liệu của dự án; kết quả tốt trên tập này **chưa** chứng minh chất lượng trên báo cáo thật. Bộ n-gram không phát hiện diễn đạt lại (tỷ lệ báo 0 trên nhóm `paraphrase` của `pairs.jsonl`), còn cosine cũ báo được 75% nhưng đồng thời báo nhầm 38% cặp cùng chủ đề — phần này thuộc chế độ ngữ nghĩa.
