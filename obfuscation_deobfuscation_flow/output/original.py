class Student:
    def __init__(self, name, scores):
        self.name = name
        self.scores = scores  

    def average_score(self):
        return sum(self.scores.values()) / len(self.scores)

    def display_result(self):
        avg = self.average_score()
        print(f"Student: {self.name}")
        print("Scores:", self.scores)
        print(f"Average Score: {avg:.2f}")

        if avg >= 90:
            print("Grade: A")
        elif avg >= 75:
            print("Grade: B")
        elif avg >= 60:
            print("Grade: C")
        else:
            print("Grade: F")
        print("------")

def main():
    print("== Automated Student Grading ==")

    students = [
        Student("Alice", {"Math": 95, "English": 88, "Science": 91}),
        Student("Bob", {"Math": 60, "English": 55, "Science": 65}),
        Student("Charlie", {"Math": 78, "English": 82, "Science": 80})
    ]

    for student in students:
        student.display_result()

if __name__ == "__main__":
    main()
