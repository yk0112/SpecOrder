# コンパイラの定義
CC = clang-sf

# コンパイルオプション
# CFLAGS = -emit-llvm -g -c

# ソースファイル
SOURCE = test.c

# 出力ファイル
OUTPUT = test.sf.o

SF_CFLAGS := -fsanitize=address -O3 -ggdb --enable-coverage

# デフォルトターゲット
all: $(OUTPUT)

# コンパイルコマンド
$(OUTPUT): $(SOURCE)
	$(CC) $(SF_CFLAGS) $(SOURCE) -o $(OUTPUT)

# クリーンターゲット（生成ファイルの削除）
clean:
	rm -f $(OUTPUT)

# 再コンパイルターゲット
rebuild: clean all

