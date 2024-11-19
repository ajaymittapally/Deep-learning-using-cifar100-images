import tensorflow as tf
from tensorflow.keras import layers, models, optimizers
from tensorflow.keras.applications import VGG16
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Load CIFAR-100 dataset
(x_train, y_train), (x_test, y_test) = tf.keras.datasets.cifar100.load_data()

# Normalize pixel values to be between 0 and 1
x_train, x_test = x_train / 255.0, x_test / 255.0

# Split the dataset into training and validation sets
x_train, x_val, y_train, y_val = train_test_split(x_train, y_train, test_size=0.2, random_state=42)

# Define data augmentation
datagen_train = ImageDataGenerator(
    rotation_range=20,
    width_shift_range=0.2,
    height_shift_range=0.2,
    horizontal_flip=True
)

# Create custom image classification model
def create_custom_model(base_model):
    model = models.Sequential()
    model.add(base_model)
    model.add(layers.Flatten())
    model.add(layers.Dense(256, activation='relu'))
    model.add(layers.Dropout(0.5))
    model.add(layers.Dense(100, activation='softmax'))
    return model

# Choose a deep learning architecture
base_model = VGG16(weights='imagenet', include_top=False, input_shape=(32, 32, 3))
# Alternatively, you can use ResNet50 or InceptionV3

model = create_custom_model(base_model)

# Compile the model
model.compile(optimizer=optimizers.Adam(lr=0.0001), loss='sparse_categorical_crossentropy', metrics=['accuracy'])

# Train the model with data augmentation
model.fit(datagen_train.flow(x_train, y_train, batch_size=32), epochs=10, validation_data=(x_val, y_val))

# Evaluate the model
predictions = model.predict(x_test)
y_pred = tf.argmax(predictions, axis=1).numpy()

# Display and save the classification report
class_report = classification_report(y_test, y_pred)
print("Classification Report:\n", class_report)


# Display and save the confusion matrix
conf_matrix = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(10, 8))
sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues", xticklabels=True, yticklabels=True)
plt.title("Confusion Matrix")
plt.xlabel("Predicted Labels")
plt.ylabel("True Labels")
plt.show()

# Save the model if needed
# Save the metrics to a file or include them in your report as needed
with open("classification_report.txt", "w") as file:
    file.write("Classification Report:\n" + class_report)
