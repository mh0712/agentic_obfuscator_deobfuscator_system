class GradeCalculator:
    def __init__(self):
        self.grades = []

    def add_grade(self, grade):
        if 0 <= grade <= 100:
            self.grades.append(grade)
        else:
            print(f"Can't Add {grade}! the value must be between 0 and 100.")
            

    def calculate_average(self):
        if not self.grades:
            return 0
        return sum(self.grades) / len(self.grades)

calculator = GradeCalculator()
calculator.add_grade(85)
calculator.add_grade(120)
calculator.add_grade(78)
average = calculator.calculate_average()
print("Average grade:", average)
