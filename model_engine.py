from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import numpy as np

class NIDSModel:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.accuracy = 0.0
        self.is_trained = False

    def train(self, df):
        """
        Trains the Random Forest model on the provided dataframe.
        Assumes 'Class' is the target column.
        """
        # Feature selection
        X = df.drop('Class', axis=1)
        y = df['Class']
        
        # Split Data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        
        # Train
        self.model.fit(X_train, y_train)
        
        # Evaluate
        preds = self.model.predict(X_test)
        self.accuracy = accuracy_score(y_test, preds)
        self.is_trained = True
        
        return self.accuracy

    def predict_packet(self, packet_data):
        """
        Predicts if a single packet is Benign (0) or Malicious (1).
        packet_data: list or numpy array of features
        """
        if not self.is_trained:
            raise Exception("Model not trained yet.")
            
        # Reshape input for sklearn (1 sample, n features)
        input_array = np.array(packet_data).reshape(1, -1)
        prediction = self.model.predict(input_array)[0]
        return prediction
    