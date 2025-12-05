import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

df = pd.read_csv("sms_spam.csv", encoding="ISO-8859-1")
 
# columns: ['', '']
# v1 → label (“ham” = normal message, “spam” = unwanted message)
# v2 → actual text message

X = df['v2']   
y = df['v1']   

# TF-IDF converts each message into a vector e.g:0.3=hello

vectorizer = TfidfVectorizer(stop_words='english')
X_vec = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2)

model = MultinomialNB()
model.fit(X_train, y_train)

print("Accuracy:", model.score(X_test, y_test))

joblib.dump(model, "spam_model.joblib")
joblib.dump(vectorizer, "vectorizer.joblib")

print("Model saved.")
