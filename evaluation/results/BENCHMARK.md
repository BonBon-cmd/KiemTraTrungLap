# Đo đối chiếu từ vựng trên dữ liệu tổng hợp có đáp án

Kho 137 đoạn, 276 đoạn bài nộp (test: 138). Ngưỡng của các bộ máy n-gram chọn trên validation.

| Bộ máy | Ngưỡng | Precision | Recall | F1 | Báo nhầm (cùng lĩnh vực) | Báo nhầm (khác lĩnh vực) | Bắt: chép nửa | sửa 30% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| cosine cũ (0,08, không ràng buộc) | 0.08 | 0.493 | 1.000 | 0.660 | 1.000 | 1.000 | 1.00 | 1.00 |
| cosine + cụm 4 từ (bản trước) | 0.08 | 0.840 | 1.000 | 0.913 | 0.224 | 0.000 | 1.00 | 1.00 |
| n-gram n=3, từ nội dung>=0 | 0.23 | 0.932 | 1.000 | 0.965 | 0.086 | 0.000 | 1.00 | 1.00 |
| n-gram n=3, từ nội dung>=1 | 0.23 | 0.932 | 1.000 | 0.965 | 0.086 | 0.000 | 1.00 | 1.00 |
| n-gram n=3, từ nội dung>=2 | 0.23 | 0.944 | 1.000 | 0.971 | 0.069 | 0.000 | 1.00 | 1.00 |
| n-gram n=4, từ nội dung>=0 | 0.29 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 1.00 | 1.00 |
| n-gram n=4, từ nội dung>=1 | 0.29 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 1.00 | 1.00 |
| n-gram n=4, từ nội dung>=2 | 0.29 | 1.000 | 0.985 | 0.993 | 0.000 | 0.000 | 1.00 | 0.93 |
| n-gram n=5, từ nội dung>=0 | 0.16 | 1.000 | 0.985 | 0.993 | 0.000 | 0.000 | 1.00 | 0.93 |
| n-gram n=5, từ nội dung>=1 | 0.16 | 1.000 | 0.985 | 0.993 | 0.000 | 0.000 | 1.00 | 0.93 |
| n-gram n=5, từ nội dung>=2 | 0.16 | 1.000 | 0.985 | 0.993 | 0.000 | 0.000 | 1.00 | 0.93 |

## Tỷ lệ cặp được báo trên evaluation/pairs.jsonl (nhãn tay)

| Bộ máy | chép nguyên văn | diễn đạt lại | cùng chủ đề | khác chủ đề |
|---|---:|---:|---:|---:|
| n-gram n=3, từ nội dung>=0 | 1.00 | 0.00 | 0.00 | 0.00 |
| n-gram n=3, từ nội dung>=1 | 1.00 | 0.00 | 0.00 | 0.00 |
| n-gram n=3, từ nội dung>=2 | 1.00 | 0.00 | 0.00 | 0.00 |
| n-gram n=4, từ nội dung>=0 | 1.00 | 0.00 | 0.00 | 0.00 |
| n-gram n=4, từ nội dung>=1 | 1.00 | 0.00 | 0.00 | 0.00 |
| n-gram n=4, từ nội dung>=2 | 1.00 | 0.00 | 0.00 | 0.00 |
| n-gram n=5, từ nội dung>=0 | 1.00 | 0.00 | 0.00 | 0.00 |
| n-gram n=5, từ nội dung>=1 | 1.00 | 0.00 | 0.00 | 0.00 |
| n-gram n=5, từ nội dung>=2 | 1.00 | 0.00 | 0.00 | 0.00 |
| cosine cũ (0,08, không ràng buộc) | 1.00 | 0.75 | 0.38 | 0.00 |
| cosine + cụm 4 từ (bản trước) | 1.00 | 0.00 | 0.00 | 0.00 |

## Sai số tuyệt đối trung bình của con số tổng (so với tỷ lệ chép thật)

- chunk_ratio_cosine: 0.173
- chunk_ratio_ngram: 0.046
- word_index_ngram: 0.020

## Tốc độ

- Kho 10000 đoạn, 150 truy vấn: n-gram dựng chỉ mục 0.3s + tìm 0.0s; cosine ước tính 14s.
