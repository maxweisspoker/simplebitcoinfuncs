from setuptools import setup, find_packages

setup(
    name='simplebitcoinfuncs',
    version='0.1.4.5',
    install_requires=['pbkdf2'],
    description='Simple Python 2/3 functions for common Bitcoin operations',
    url='https://github.com/maxweisspoker/simplebitcoinfuncs',
    keywords='bitcoin',
    author='Maximilian Weiss',
    author_email='max@maxweiss.io',
    license='MIT',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'
    ],
)

