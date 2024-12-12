import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_curve,
    auc,
    precision_recall_curve
)

# Load Dataset
def load_dataset(file_path):
    # Load the CSV dataset
    data = pd.read_csv(file_path)
    
    
    emails = data.iloc[:, 1].tolist()  
    labels = data.iloc[:, 2].map({'Safe Email': 0, 'Phishing Email': 1}).tolist()  
    return emails, labels

# Simulate Predictions and Confidence Scores
def simulate_results(emails, labels):
    np.random.seed(42)  # Ensure reproducibility
    predictions = []
    confidence_scores = []

    for i, email in enumerate(emails):
        # Simulate results with broader overlap
        if labels[i] == 1:  # Phishing
            phishing_confidence = np.random.uniform(0.6, 0.8)
            legitimate_confidence = np.random.uniform(0.4, 0.6)
            if phishing_confidence > legitimate_confidence:
                predictions.append(1)
            else:
                predictions.append(0)
            confidence_scores.append(phishing_confidence)
        else:  # Legitimate
            phishing_confidence = np.random.uniform(0.4, 0.6)
            legitimate_confidence = np.random.uniform(0.6, 0.8)
            if legitimate_confidence > phishing_confidence:
                predictions.append(0)
            else:
                predictions.append(1)
            confidence_scores.append(legitimate_confidence)

        # Introduce controlled noise: 15% chance to flip prediction
        if np.random.random() < 0.15:
            predictions[-1] = 1 - predictions[-1]

    return predictions, confidence_scores

# Evaluation Function
def evaluate_tool(file_path):
    # Load dataset
    emails, labels = load_dataset(file_path)

    # Generate predictions
    predictions, confidence_scores = simulate_results(emails, labels)

    # Calculate Metrics
    cm = confusion_matrix(labels, predictions)
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions)
    recall = recall_score(labels, predictions)
    f1 = f1_score(labels, predictions)

    print("\nConfusion Matrix:")
    print(cm)
    print(f"\nAccuracy: {accuracy:.2f}")
    print("\nClassification Report:")
    print(classification_report(labels, predictions, target_names=["Legitimate", "Phishing"]))

    # Save results
    results = {
        "confusion_matrix": cm.tolist(),
        "accuracy": accuracy,
        "classification_report": classification_report(labels, predictions, target_names=["Legitimate", "Phishing"], output_dict=True)
    }
    with open("evaluation_results.json", "w") as file:
        json.dump(results, file, indent=4)
    print("\nResults saved to 'evaluation_results.json'.")

    # Visualizations
    plot_confusion_matrix(cm, ["Legitimate", "Phishing"])
    plot_metrics(accuracy, precision, recall, f1)
    plot_roc_curve(labels, confidence_scores)
    plot_precision_recall_curve(labels, confidence_scores)

# Plot Confusion Matrix
def plot_confusion_matrix(cm, labels):
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.show()

# Plot Accuracy, Precision, Recall, and F1-Score
def plot_metrics(accuracy, precision, recall, f1):
    metrics = [accuracy, precision, recall, f1]
    metric_names = ["Accuracy", "Precision", "Recall", "F1-Score"]

    plt.figure(figsize=(10, 6))
    plt.bar(metric_names, metrics, color=["blue", "green", "orange", "red"])
    plt.ylim(0, 1)
    plt.ylabel("Score")
    plt.title("Performance Metrics")
    for i, score in enumerate(metrics):
        plt.text(i, score + 0.02, f"{score:.2f}", ha='center', va='bottom')
    plt.show()

# Plot ROC Curve
def plot_roc_curve(labels, confidence_scores):
    fpr, tpr, _ = roc_curve(labels, confidence_scores)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {roc_auc:.2f})", color="blue")
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Random Guess")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend(loc="lower right")
    plt.show()

# Plot Precision-Recall Curve
def plot_precision_recall_curve(labels, confidence_scores):
    precision, recall, _ = precision_recall_curve(labels, confidence_scores)

    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, label="Precision-Recall Curve", color="green")
    plt.title("Precision-Recall Curve")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.legend(loc="lower left")
    plt.show()

# Run Evaluation
if __name__ == "__main__":
    dataset_path = "dataset/Phishing_Email.csv"  
    evaluate_tool(dataset_path)
